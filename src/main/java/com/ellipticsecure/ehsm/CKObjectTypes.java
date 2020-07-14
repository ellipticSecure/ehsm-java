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
 * CK Object types.
 * @author Kobus Grobler
 */
public class CKObjectTypes {
    private CKObjectTypes() {
    }

    public static final long CKO_DATA = 0x00000000L;
    public static final long CKO_CERTIFICATE = 0x00000001L;
    public static final long CKO_PUBLIC_KEY = 0x00000002L;
    public static final long CKO_PRIVATE_KEY = 0x00000003L;
    public static final long CKO_SECRET_KEY = 0x00000004L;

}
