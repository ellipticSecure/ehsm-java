/*
 * Copyright (c) 2021 Elliptic
 *
 *  All rights reserved.
 *
 *  You may only use this code under the terms of the Elliptic license.
 *
 */

package com.ellipticsecure.ehsm;

public class CKKeyTypes {
    private CKKeyTypes() {}

    public static final long  CKK_RSA                  = 0x00000000L;
    public static final long  CKK_DSA                  = 0x00000001L;
    public static final long  CKK_DH                   = 0x00000002L;
    public static final long  CKK_EC                   = 0x00000003L;
    public static final long  CKK_GENERIC_SECRET       = 0x00000010L;
    public static final long  CKK_DES                  = 0x00000013L;
    public static final long  CKK_DES2                 = 0x00000014L;
    public static final long  CKK_DES3                 = 0x00000015L;
    public static final long  CKK_AES                  = 0x0000001FL;
    public static final long  CKK_VENDOR_DEFINED       = 0x80000000L;
}
