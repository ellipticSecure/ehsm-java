/*
 * Copyright (c) 2020 Elliptic
 *
 *  All rights reserved.
 *
 *  You may only use this code under the terms of the Elliptic license.
 *
 */

package com.ellipticsecure.ehsm;

/**
 * Partial set of CK defined flags
 * @author Kobus Grobler
 */
public class CKFlags {
    private CKFlags() { }

    public static final long CKF_USER_PIN_INITIALIZED = 0x00000008L;
    public static final long CKF_TOKEN_INITIALIZED = 0x00000400L;
    public static final long CKF_RW_SESSION = 0x00000002L; /* session is r/w */
    public static final long CKF_SERIAL_SESSION = 0x00000004L; /* no parallel */
}
