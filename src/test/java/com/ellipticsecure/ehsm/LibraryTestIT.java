/*
 * Copyright (c) 2020 Elliptic
 *
 *  All rights reserved.
 *
 *  You may only use this code under the terms of the Elliptic license.
 *
 */

package com.ellipticsecure.ehsm;

import com.sun.jna.Memory;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.NativeLongByReference;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.NoSuchElementException;

import static com.ellipticsecure.ehsm.CKAttribute.*;
import static com.ellipticsecure.ehsm.CKFlags.*;
import static com.ellipticsecure.ehsm.CKObjectTypes.CKO_CERTIFICATE;
import static com.ellipticsecure.ehsm.CKReturnValues.*;
import static com.ellipticsecure.ehsm.CKUserTypes.CKU_SO;
import static com.ellipticsecure.ehsm.CKUserTypes.CKU_USER;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration Test for the eHSM library.
 * NOTE: !!! This test will destroy key material on the connected device !!!
 *
 * @author Kobus Grobler
 */
@Slf4j
class LibraryTestIT {

    private static final String TEST_PIN = "testsu";
    private static final String TEST_SO_PIN = "testso";
    private static final String ELLIPTIC_SECURE = "ellipticSecure";

    private static EHSMLibrary lib;

    private NativeLong slot;

    @BeforeAll
    public static void setupClass() {
        lib = EHSMLibrary.getInstance(EHSMLibrary.getDefaultLibraryName());
    }

    @BeforeEach
    public void setup() {
        lib.C_Finalize(Pointer.NULL);
        long r = lib.C_Initialize(Pointer.NULL);
        assertEquals(CKR_OK, r,"C_Initialize returned 0x" + Long.toHexString(r));

        CKInfo libInfo = new CKInfo();
        r = lib.C_GetInfo(libInfo);
        assertEquals(CKR_OK, r,"C_GetInfo returned 0x" + Long.toHexString(r));
        log.trace("CKInfo: {}",libInfo);
        assertTrue(libInfo.cryptokiVersion.major >=2, "Invalid CK version");
        assertTrue(libInfo.libraryVersion.major >=2, "Invalid library version");
        if (libInfo.libraryVersion.major == 2) {
            assertTrue(libInfo.libraryVersion.minor >= 1, "Invalid library version");
        }
        assertEquals(ELLIPTIC_SECURE, libInfo.getManufacturerID(),"Invalid manufacturer ID");

        slot = getPresentSlot();
        CKTokenInfo info = new CKTokenInfo();
        r = lib.C_GetTokenInfo(slot, info);
        assertEquals(CKR_OK, r, "C_GetTokenInfo returned 0x" + Long.toHexString(r));
        log.trace("CKTokenInfo: {}",info);
        if ((info.flags.longValue() & CKF_TOKEN_INITIALIZED) == 0) {
            log.info("Device not initialized yet, doing it now.");

            r = lib.C_InitToken(slot,TEST_SO_PIN,new NativeLong(TEST_SO_PIN.length()),
                    String.format("%1$-32s", "testtoken"));
            assertEquals(CKR_OK, r, "C_InitToken returned 0x" + Long.toHexString(r));
        }

        if ((info.flags.longValue() & CKF_USER_PIN_INITIALIZED) == 0) {
            log.info("Device has no PIN set, doing it now.");
            NativeLong session = getLoggedInSession(slot, 6, CKU_SO, TEST_SO_PIN);
            r = lib.C_InitPIN(session, TEST_PIN, new NativeLong(TEST_PIN.length()));
            assertEquals(CKR_OK, r, "C_InitPIN returned 0x" + Long.toHexString(r));
            lib.C_CloseSession(session);
        }
    }

    @AfterEach
    public void tearDown() {
        lib.C_Finalize(Pointer.NULL);
    }

    private NativeLong getPresentSlot() {
        NativeLong[] pSlotList = new NativeLong[10];
        NativeLongByReference pCount = new NativeLongByReference(new NativeLong(pSlotList.length));
        long r = lib.C_GetSlotList((byte) 1, pSlotList, pCount);
        assertEquals(CKR_OK, r, "C_GetSlotList returned 0x" + Long.toHexString(r));

        if (pCount.getValue().longValue() == 0) {
            fail("No available slots found.");
        }
        return pSlotList[0];
    }

    private NativeLong getLoggedInSession(NativeLong slot, long type, long user, String pin) {
        NativeLongByReference pSession = new NativeLongByReference();
        // rw session
        long r = lib.C_OpenSession(slot, new NativeLong(type), Pointer.NULL, Pointer.NULL, pSession);
        assertEquals(CKR_OK, r, "Failed to create session: 0x" + Long.toHexString(r));
        r = lib.C_Login(pSession.getValue(), new NativeLong(user), pin, new NativeLong(pin.length()));
        assertEquals(CKR_OK, r, "Failed to log in: 0x" + Long.toHexString(r));
        return pSession.getValue();
    }

    @Test
    void tokenInfo() {
        log.info("token info test.");
        CKTokenInfo info = new CKTokenInfo();
        long r = lib.C_GetTokenInfo(slot, info);
        assertEquals(CKR_OK, r, "C_GetTokenInfo returned 0x" + Long.toHexString(r));
        log.info("Token info:{}", info);
        assertEquals(ELLIPTIC_SECURE, info.getManufacturerID(), "Manufacturer ID is invalid.");
    }

    @Test
    void findObjects() throws IOException {
        log.info("Find objects test.");
        NativeLong session = getLoggedInSession(slot,CKF_SERIAL_SESSION, CKU_USER, TEST_PIN);

        // this ensures contiguous native structure memory
        CKAttribute []attributes = (CKAttribute [])new CKAttribute().toArray(2);
        CKAttribute.setLongAttribute(attributes[0],CKA_CLASS,CKO_CERTIFICATE);
        CKAttribute.setBoolAttribute(attributes[1],CKA_TOKEN,true);
        CKAttribute []getattr = (CKAttribute [])new CKAttribute().toArray(1);
        CKAttribute.setBoolAttribute(getattr[0],CKA_PRIVATE,false);
        try (ObjectHandleIterator it = new ObjectHandleIterator(lib,session,attributes)) {
            while (it.hasNext()) {
                NativeLong obj = it.next();
                log.debug("objectHandle {}", obj);
                EHSMLibrary.throwIfNotOK(lib.C_GetAttributeValue(session,obj,getattr,new NativeLong(getattr.length)));
                log.debug("type: "+getattr[0].type+" len:"+getattr[0].ulValueLen+" val:"+getattr[0].pValue.getByte(0));
            }
            // iterate past end and ensure throw
            assertThrows(NoSuchElementException.class, it::next);
        }
    }

    @Test
    void configTest() {
        log.info("config test.");
        EHSMConfig config = new EHSMConfig();
        long r = lib.u32GetTokenConfig(slot,config);
        assertEquals(CKR_OK, r, "u32GetTokenConfig returned 0x" + Long.toHexString(r));
        log.info("Config: {}",config);

        NativeLong session = getLoggedInSession(slot,CKF_RW_SESSION | CKF_SERIAL_SESSION, CKU_SO, TEST_SO_PIN);

        short options =  config.u16BitOptions;
        byte sessionTimeout = config.u8SessionTimeout;

        r = lib.u32SetBitOptions(slot,(short)0);
        assertEquals(CKR_OK, r, "u32SetBitOptions returned 0x" + Long.toHexString(r));

        r = lib.u32SetSessionTimeout(slot,(byte)10);
        assertEquals(CKR_OK, r, "u32SetSessionTimeout returned 0x" + Long.toHexString(r));

        r = lib.u32GetTokenConfig(slot,config);
        assertEquals(CKR_OK, r, "u32GetTokenConfig returned 0x" + Long.toHexString(r));
        log.info("Config: {}",config);
        assertEquals(0, config.u16BitOptions,"u32GetTokenConfig expected 0 for options but got 0x" + Long.toHexString(config.u16BitOptions));
        assertEquals(10, config.u8SessionTimeout, "u32GetTokenConfig expected 0 for timeout but got 0x" + Long.toHexString(config.u8SessionTimeout));

        // set original value
        r = lib.u32SetBitOptions(slot,options);
        assertEquals(CKR_OK, r, "u32SetBitOptions returned 0x" + Long.toHexString(r));
        r = lib.u32SetSessionTimeout(slot,sessionTimeout);
        assertEquals(CKR_OK, r, "u32SetSessionTimeout returned 0x" + Long.toHexString(r));

        lib.C_CloseSession(session);

    }

    @Test
    void factoryReset() {
        log.info("Factory reset test.");
        long r = lib.u32FactoryReset(slot);
        // should return CKR_ACTION_PROHIBITED unless button is pressed during test
        assertEquals(CKR_ACTION_PROHIBITED, r, "u32FactoryReset returned 0x" + Long.toHexString(r));
    }

    @Test
    void randomTest() {
        log.info("Performing random test.");
        NativeLong session = getLoggedInSession(slot, CKF_RW_SESSION | CKF_SERIAL_SESSION, CKU_SO, TEST_SO_PIN);
        byte[] rnd = new byte[16];
        long r = lib.C_GenerateRandom(session,rnd,new NativeLong(rnd.length));
        assertEquals(CKR_OK, r, "C_GenerateRandom returned 0x" + Long.toHexString(r));
        log.info("Rnd value {}",Hex.encodeHexString(rnd));
    }

    @Test
    void cryptoTest() {
        log.info("Performing crypto test.");
        NativeLong session = getLoggedInSession(slot, CKF_RW_SESSION | CKF_SERIAL_SESSION, CKU_USER, TEST_PIN);

        CKAttribute []attributes = (CKAttribute [])new CKAttribute().toArray(4);
        CKAttribute.setLongAttribute(attributes[0],CKA_VALUE_LEN,32);
        CKAttribute.setBoolAttribute(attributes[1],CKA_TOKEN,false);
        CKAttribute.setBoolAttribute(attributes[2],CKA_ENCRYPT,true);
        CKAttribute.setBoolAttribute(attributes[3],CKA_DECRYPT,true);

        NativeLongByReference phKey = new NativeLongByReference();
        CKMechanism mech = CKMechanism.create(CKMechanism.CKM_AES_KEY_GEN,Pointer.NULL,0);
        long r = lib.C_GenerateKey(session,mech,attributes,new NativeLong(attributes.length),phKey);
        assertEquals(CKR_OK, r, "C_GenerateKey returned 0x" + Long.toHexString(r));

        byte[] rnd = new byte[16];
        r = lib.C_GenerateRandom(session,rnd,new NativeLong(rnd.length));
        assertEquals(CKR_OK, r, "C_GenerateRandom returned 0x" + Long.toHexString(r));
        Memory iv = new Memory(rnd.length);
        iv.write(0,rnd,0,rnd.length);
        mech = CKMechanism.create(CKMechanism.CKM_AES_CBC_PAD,iv,iv.size());

        r = lib.C_EncryptInit(session,mech,phKey.getValue());
        assertEquals(CKR_OK, r, "C_EncryptInit returned 0x" + Long.toHexString(r));
        String clearText ="Hello World!";
        byte[] data = clearText.getBytes();
        //byte[] data = new byte[32];
        //Arrays.fill(data,(byte)1);
        byte[] enc = new byte[128];
        NativeLongByReference encLen = new NativeLongByReference(new NativeLong(enc.length));
        r = lib.C_Encrypt(session,data,new NativeLong(data.length),enc,encLen);
        assertEquals(CKR_OK, r, "C_Encrypt returned 0x" + Long.toHexString(r));

        r = lib.C_DecryptInit(session,mech,phKey.getValue());
        assertEquals(CKR_OK, r, "C_DecryptInit returned 0x" + Long.toHexString(r));

        byte[] dec = new byte[128];
        r = lib.C_Decrypt(session,enc,encLen.getValue(),dec,encLen);
        assertEquals(CKR_OK, r, "C_Decrypt returned 0x" + Long.toHexString(r));
        String decStr = new String(dec,0,encLen.getValue().intValue());
        assertEquals(clearText,decStr);
        r = lib.C_DestroyObject(session,phKey.getValue());
        assertEquals(CKR_OK, r, "C_DestroyObject returned 0x" + Long.toHexString(r));
    }

    @Test
    void initPinTest() {
        log.info("Performing PIN test.");

        NativeLong session = getLoggedInSession(slot, CKF_RW_SESSION | CKF_SERIAL_SESSION, CKU_SO, TEST_SO_PIN);
        String newSuPin = "newsupin";
        long r = lib.C_InitPIN(session, newSuPin, new NativeLong(newSuPin.length()));
        assertEquals(CKR_OK, r, "C_InitPIN returned 0x" + Long.toHexString(r));

        r = lib.C_CloseSession(session);
        assertEquals(CKR_OK, r, "C_CloseSession returned 0x" + Long.toHexString(r));

        session = getLoggedInSession(slot, CKF_RW_SESSION | CKF_SERIAL_SESSION, CKU_USER, newSuPin);

        // revert back so other tests dont fail
        r = lib.C_InitPIN(session, TEST_PIN, new NativeLong(TEST_PIN.length()));
        assertEquals(CKR_OK, r,"C_InitPIN returned 0x" + Long.toHexString(r));
    }

    @Test
    void btcTest() throws DecoderException {
        log.info("Performing btc test....");

        NativeLong session = getLoggedInSession(slot, CKF_RW_SESSION | CKF_SERIAL_SESSION, CKU_USER, TEST_PIN);

        NativeLongByReference pBTCHandle = new NativeLongByReference();
        long r = lib.u32HasBitcoinKey(session, pBTCHandle);
        if (r == CKR_OK) {
            log.info("deleting btc key.");
            r = lib.C_DestroyObject(session, pBTCHandle.getValue());
            assertEquals(CKR_OK,r);
            r = lib.u32HasBitcoinKey(session, pBTCHandle);
            if (r == CKR_OK)
                log.debug("BTC Handle: {}",pBTCHandle.getValue());
            assertEquals(BTC_KEY_NOT_FOUND, r, "Expected BTC_KEY_NOT_FOUND but got 0x" + Long.toHexString(r));
        } else if (r == BTC_KEY_NOT_FOUND) {
            // OK.
            log.debug("btc key not found.");
        } else {
            fail("Failed to get btc key: 0x" + Long.toHexString(r));
        }

        byte[] key = Hex.decodeHex("000102030405060708090a0b0c0d0e0f");
        r = lib.u32ImportBitcoinKey(session, key, new NativeLong(key.length));
        assertEquals(CKR_OK, r, "Failed to import btc key: 0x" + Long.toHexString(r));


        // perform BIP32 tests from test vectors defined in https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

        int net = 0x0488B21E; // main net
        int[] indexes = {};
        String xpub = EHSMLibrary.GetBIP32XPub(lib,session,net,indexes);
        assertEquals("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
                xpub);

        indexes = new int[]{0x80000000};
        xpub = EHSMLibrary.GetBIP32XPub(lib,session,net,indexes);
        assertEquals("xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",xpub);

        indexes = new int[]{0x80000000,1};
        xpub = EHSMLibrary.GetBIP32XPub(lib,session,net,indexes);
        assertEquals("xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",xpub);

        indexes = new int[]{0x80000000,1,0x80000002};
        xpub = EHSMLibrary.GetBIP32XPub(lib,session,net,indexes);
        assertEquals("xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",xpub);

        indexes = new int[]{0x80000000,1,0x80000002, 2};
        xpub = EHSMLibrary.GetBIP32XPub(lib,session,net,indexes);
        assertEquals("xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",xpub);

        indexes = new int[]{0x80000000,1,0x80000002, 2, 1000000000};
        xpub = EHSMLibrary.GetBIP32XPub(lib,session,net,indexes);
        assertEquals("xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",xpub);
    }
}
