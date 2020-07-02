/*
 * Copyright (c) 2020 Elliptic
 *
 *  All rights reserved.
 *
 *  You may only use this code under the terms of the Elliptic license.
 *
 */

package com.ellipticsecure.ehsm;

public class CKReturnValues {
    private CKReturnValues() {}
    public static final long CKR_OK = 0;
    public static final long CKR_ARGUMENTS_BAD = 0x00000007L;
    public static final long CKR_ACTION_PROHIBITED = 0x0000001BL;
    public static final long CKR_USER_NOT_LOGGED_IN = 0x00000101L;
    public static final long CKR_VENDOR_DEFINED = 0x80000000L;
    public static final long BTC_KEY_NOT_FOUND = CKR_VENDOR_DEFINED+1;
    public static final long BTC_KEY_ALREADY_EXISTS = BTC_KEY_NOT_FOUND+1;
}
