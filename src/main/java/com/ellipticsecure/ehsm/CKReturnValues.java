/*
 * Copyright (c) 2020 Elliptic
 *
 *  All rights reserved.
 *
 *  You may only use this code under the terms of the Elliptic license.
 *
 */

package com.ellipticsecure.ehsm;

import java.util.HashMap;
import java.util.Map;

/**
 * Defines a subset of the CK return values.
 *
 * @author Kobus Grobler
 */
public class CKReturnValues {
    private CKReturnValues() {
    }

    public static final long CKR_OK = 0;
    public static final long CKR_FUNCTION_FAILED = 0x6L;
    public static final long CKR_ARGUMENTS_BAD = 0x00000007L;
    public static final long CKR_ACTION_PROHIBITED = 0x0000001BL;
    public static final long CKR_OBJECT_HANDLE_INVALID = 0x82L;
    public static final long CKR_PIN_INCORRECT = 0xA0;
    public static final long CKR_USER_NOT_LOGGED_IN = 0x00000101L;
    public static final long CKR_USER_PIN_NOT_INITIALIZED = 0x102L;
    public static final long CKR_CRYPTOKI_NOT_INITIALIZED = 0x190L;
    public static final long CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x191L;
    public static final long CKR_VENDOR_DEFINED = 0x80000000L;
    public static final long BTC_KEY_NOT_FOUND = CKR_VENDOR_DEFINED + 1;
    public static final long BTC_KEY_ALREADY_EXISTS = BTC_KEY_NOT_FOUND + 1;

    /**
     * Returns a text message for the specified CryptoKey return code.
     * Note: not all CKR have been assigned individual messages here.
     *
     * @param ckr the CKR_xxx code
     * @return a text message for the specified CryptoKey return code.
     */
    public static String getErrorMessage(long ckr) {
        String msg = messages.get(ckr);
        if (msg == null) {
            msg = "CK Error code 0x"+Long.toHexString(ckr);
        }
        return msg;
    }

    private static final Map<Long, String> messages  = new HashMap<>();

    static {
        messages.put(BTC_KEY_ALREADY_EXISTS, "BIP32 key already exists");
        messages.put(BTC_KEY_NOT_FOUND, "BIP32 Key not found");
        messages.put(CKR_CRYPTOKI_ALREADY_INITIALIZED,"Library already initialized");
        messages.put(CKR_CRYPTOKI_NOT_INITIALIZED, "Library not initialized");
        messages.put(CKR_USER_PIN_NOT_INITIALIZED, "User PIN not initialized");
        messages.put(CKR_USER_NOT_LOGGED_IN, "User not logged in");
        messages.put(CKR_PIN_INCORRECT, "Incorrect PIN");
        messages.put(CKR_OBJECT_HANDLE_INVALID, "Object handle is invalid");
        messages.put(CKR_ACTION_PROHIBITED,"Action prohibited");
        messages.put(CKR_ARGUMENTS_BAD, "Invalid function arguments");
        messages.put(CKR_FUNCTION_FAILED, "Function failed");
        messages.put(CKR_OK, "OK");
    }

}
