/*
 * Copyright (c) 2020 Elliptic
 *
 *  All rights reserved.
 *
 *  You may only use this code under the terms of the Elliptic license.
 *
 */

package com.ellipticsecure.ehsm;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.NativeLongByReference;
import lombok.NonNull;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import static com.ellipticsecure.ehsm.CKReturnValues.CKR_OK;

/**
 * This is a low level interface for the eHSM shared library.
 *
 * It is recommended that the standard SunPKCS11 provider be used to perform cryptographic operations
 * and this library only for eHSM specific functions.
 *
 * @author Kobus Grobler
 */
public interface EHSMLibrary extends Library {

    /**
     * Retrieves an instance of the EHSMLibrary.
     *
     * @param libraryName the name of the shared library file - see getDefaultLibraryName().
     * @return an instance.
     */
    static EHSMLibrary getInstance(@NonNull String libraryName) {
        return Native.load(libraryName, EHSMLibrary.class);
    }

    /**
     * A Utility method that checks the return code from a method and throws EHSMException if it is not CKR_OK.
     * @param ckr the CK return code
     */
    static void throwIfNotOK(long ckr) {
        if (ckr != CKR_OK) {
            throw new EHSMException(CKReturnValues.getErrorMessage(ckr),ckr);
        }
    }

    // Device management functions follow

    /**
     * Performs a factory reset. By default (depending on settings) requires a user action to be performed first,
     * i.e. a button press.
     *
     * C: uint32_t u32FactoryReset(CK_SLOT_ID slot)
     *
     * @param slot the slot ID
     * @return a CKR result code, CKR_OK if success.
     */
    long u32FactoryReset(NativeLong slot);

    /**
     * Retrieves the device specific token configuration.
     *
     * C: uint32_t u32GetTokenConfig(CK_SLOT_ID slot, tEHSMConfig *config)
     *
     * @param slot the slot ID
     * @param config the device config
     * @return a CKR result code, CKR_OK if success.
     */
    long u32GetTokenConfig(NativeLong slot, EHSMConfig config);


    /**
     * Sets the bit options field.
     * The SO user needs to be logged in prior to this call.
     *
     * 0xFFFF are all default bits.
     *
     * C: uint32_t u32SetBitOptions(CK_SLOT_ID slot, uint16_t bitOptions)
     *
     * @param slot the slot ID
     * @param bitOptions the bit options field.
     * @return CKR_OK if success or another CKR result code if it fails.
     */
    long u32SetBitOptions(NativeLong slot, short bitOptions);

    /**
     * Sets the session timeout in minutes. "0" means no timeout.
     * C: uint32_t u32SetSessionTimeout(CK_SLOT_ID slot, uint8_t mins)
     *
     * @param slot the slot ID
     * @param mins the session timeout in minutes
     * @return CKR_OK if success or another CKR result code if it fails.
     */
    long u32SetSessionTimeout(NativeLong slot, byte mins);

    // BTC specific functions follow

    /**
     * Check if the device as a bitcoin key set.
     *
     * C: uint32_t u32HasBitcoinKey(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE *handle)
     *
     * @param hSession the session handle.
     * @param handle if a BTC key exists it's handle will be returned here.
     * @return BTC_KEY_NOT_FOUND if no BTC key is found, CKR_OK if a key is found (handle will be valid) or another
     * CKR_XX error code.
     */
    long u32HasBitcoinKey(NativeLong hSession, NativeLongByReference handle);

    /**
     * Import a BTC key from the specified seed.
     *
     * C: uint32_t u32ImportBitcoinKey(CK_SESSION_HANDLE session, const uint8_t* seedIn, size_t seedLen)
     *
     * @param hSession the session handle.
     * @param seedIn the seed.
     * @param seedLen the length of the seed.
     * @return CKR_OK if success or another CKR result code if it fails.
     */
    long u32ImportBitcoinKey(NativeLong hSession, byte[] seedIn, NativeLong seedLen);

    //uint32_t u32GetBitcoinPub(CK_SESSION_HANDLE session, uint32_t* indexes, size_t indexCnt, uint8_t *out, size_t *outLen)

    /**
     * Get the BTC public key at the specified BIP32 path.
     *
     * @param hSession the session handle.
     * @param indexes the BIP32 path to the key.
     * @param indexCnt the number of indexes elements supplied.
     * @param out the raw binary public key (without network)
     * @param outLen the length of the public key.
     * @return CKR_OK if success or another CKR result code if it fails.
     */
    long u32GetBitcoinPub(NativeLong hSession, int[] indexes, NativeLong indexCnt, byte[] out, NativeLongByReference outLen);

    /**
     * This is a helper method to encode the public address in XPUB format.
     *
     * @param lib instance to this library.
     * @param session a session handle.
     * @param net the network used.
     * @param indexes the path to the public key.
     * @return the Base58 encoded public key (address).
     */
    static String GetBIP32XPub(@NonNull EHSMLibrary lib, @NonNull NativeLong session, int net, @NonNull int[] indexes) {
        byte[] out = new byte[128];
        NativeLongByReference outLen = new NativeLongByReference(new NativeLong(out.length));
        throwIfNotOK(lib.u32GetBitcoinPub(session, indexes, new NativeLong(indexes.length), out, outLen));
        byte[] payload = new byte[78];
        ByteBuffer buffer = ByteBuffer.wrap(payload);
        buffer.order(ByteOrder.BIG_ENDIAN);
        buffer.asIntBuffer().put(net);
        buffer.position(4);
        buffer.put(out, 0, outLen.getValue().intValue());
        return Base58.encodeChecked(payload);
    }

    /**
     * Signs a BTC hash with the specified key at the BIP32 path.
     *
     * C: uint32_t u32SignBitcoinHash(CK_SESSION_HANDLE session, const uint8_t* hash, size_t hashLen,
     *                                uint32_t* indexes, size_t indexCnt, uint8_t* sig, size_t *sigLenInOut)
     *
     * @param session the session handle.
     * @param hash the (32) byte hash to sign.
     * @param hashLen the hash length.
     * @param indexes the BIP32 path to the key.
     * @param indexCnt the number of indexes elements supplied.
     * @param sig tbe raw binary signature.
     * @param sigLenInOut the length of the signature.
     * @return CKR_OK if success or another CKR result code if it fails.
     */
    long u32SignBitcoinHash(NativeLong session, byte[] hash, NativeLong hashLen,
                            int[] indexes, NativeLong indexCnt, byte[] sig, NativeLongByReference sigLenInOut);

    // Standard PKCS11 functions follow

    // CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
    long C_Initialize(Pointer p);

    // CK_RV C_Finalize(CK_VOID_PTR pReserved)
    long C_Finalize(Pointer p);

    // CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
    long C_GetTokenInfo(NativeLong slotID, CKTokenInfo info);

    /**
     * Initializes the device.
     *
     * C: CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
     *
     * @param slotID the slot ID
     * @param pPin the SO PIN to use
     * @param ulPinLen the SO PIN length
     * @param pLabel The device label - 32 characters. Note: this should be padded with spaces if less than 32 bytes.
     * @return CKR_OK if the function succeeds.
     */
    long C_InitToken(NativeLong slotID, String pPin, NativeLong ulPinLen, String pLabel);

    //CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
    long C_GetSlotList(byte tokenPresent, NativeLong[] pSlotList, NativeLongByReference pCount);

    //CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY notify,
    //                             CK_SESSION_HANDLE_PTR phSession)
    long C_OpenSession(NativeLong slotID, NativeLong pFlags, Pointer pApplicationn, Pointer notify,
                       NativeLongByReference pSession);

    //CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
    long C_CloseSession(NativeLong hSession);

    //CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
    long C_CloseAllSessions(NativeLong slotID);

    //CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
    long C_Login(NativeLong hSession, NativeLong userType, String pPin, NativeLong ulPinLen);

    //CK_RV C_Logout(CK_SESSION_HANDLE hSession)
    long C_Logout(NativeLong hSession);

    //CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin,CK_ULONG ulNewLen
    long C_SetPIN(NativeLong hSession, String pOldPin, NativeLong ulOldLen, String pNewPin,
                  NativeLong ulNewLen);

    //CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
    long C_InitPIN(NativeLong hSession, String pPin, NativeLong ulPinLen);

    //CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
    long C_DestroyObject(NativeLong hSession, NativeLong hObject);

    //CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen)
    long C_GenerateRandom(NativeLong hSession, byte[] pRandomData, NativeLong ulRandomLen);

    /**
     * Returns the default library name for the platform.
     * @return the library name
     */
    static String getDefaultLibraryName() {
        String lib = System.getenv("EHSM_LIBRARY");
        if (lib == null) {
            String os = System.getProperty("os.name");
            if (os.toLowerCase().contains("mac")) {
                return "/usr/local/lib/libehsm.dylib";
            } else if (os.toLowerCase().contains("windows")) {
                return "ehsm.dll";
            } else {
                return "/usr/local/lib/libehsm.so";
            }
        } else {
            return lib;
        }
    }
}
