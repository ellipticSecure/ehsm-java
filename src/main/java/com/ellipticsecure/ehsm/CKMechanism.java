/*
 * Copyright (c) 2021 Elliptic
 *
 *  All rights reserved.
 *
 *  You may only use this code under the terms of the Elliptic license.
 *
 */

package com.ellipticsecure.ehsm;

import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;

@Structure.FieldOrder({"mechanism", "pParameter", "ulParameterLen"})
public class CKMechanism extends Structure {

    public static final long CKM_RSA_PKCS_KEY_PAIR_GEN =    0x00000000L;
    public static final long CKM_RSA_PKCS              =    0x00000001L;
    public static final long CKM_RSA_X_509             =    0x00000003L;
    public static final long CKM_SHA1_RSA_PKCS         =    0x00000006L;

    public static final long CKM_RIPEMD128_RSA_PKCS    =    0x00000007L;
    public static final long CKM_RIPEMD160_RSA_PKCS    =    0x00000008L;
    public static final long CKM_RSA_PKCS_OAEP         =    0x00000009L;

    public static final long CKM_SHA1_RSA_PKCS_PSS     =    0x0000000EL;

    public static final long CKM_DSA_KEY_PAIR_GEN      =    0x00000010L;
    public static final long CKM_DSA                   =    0x00000011L;
    public static final long CKM_DSA_SHA1              =    0x00000012L;
    public static final long CKM_DSA_SHA224            =    0x00000013L;
    public static final long CKM_DSA_SHA256            =    0x00000014L;
    public static final long CKM_DSA_SHA384            =    0x00000015L;
    public static final long CKM_DSA_SHA512            =    0x00000016L;

    public static final long CKM_DH_PKCS_KEY_PAIR_GEN  =    0x00000020L;
    public static final long CKM_DH_PKCS_DERIVE        =    0x00000021L;


    public static final long CKM_SHA256_RSA_PKCS       =    0x00000040L;
    public static final long CKM_SHA384_RSA_PKCS       =    0x00000041L;
    public static final long CKM_SHA512_RSA_PKCS       =    0x00000042L;
    public static final long CKM_SHA256_RSA_PKCS_PSS   =    0x00000043L;
    public static final long CKM_SHA384_RSA_PKCS_PSS   =    0x00000044L;
    public static final long CKM_SHA512_RSA_PKCS_PSS   =    0x00000045L;

    public static final long CKM_SHA224_RSA_PKCS       =    0x00000046L;
    public static final long CKM_SHA224_RSA_PKCS_PSS   =    0x00000047L;

    public static final long CKM_DES_KEY_GEN           =    0x00000120L;
    public static final long CKM_DES_ECB               =    0x00000121L;
    public static final long CKM_DES_CBC               =    0x00000122L;

    public static final long CKM_DES_CBC_PAD           =    0x00000125L;

    public static final long CKM_DES2_KEY_GEN          =    0x00000130L;
    public static final long CKM_DES3_KEY_GEN          =    0x00000131L;
    public static final long CKM_DES3_ECB              =    0x00000132L;
    public static final long CKM_DES3_CBC              =    0x00000133L;

    public static final long CKM_MD5                   =    0x00000210L;

    public static final long CKM_MD5_HMAC              =    0x00000211L;

    public static final long CKM_SHA_1                 =    0x00000220L;

    public static final long CKM_SHA_1_HMAC            =    0x00000221L;

    public static final long CKM_SHA256                =    0x00000250L;
    public static final long CKM_SHA256_HMAC           =    0x00000251L;
    public static final long CKM_SHA256_HMAC_GENERAL   =    0x00000252L;
    public static final long CKM_SHA224                =    0x00000255L;
    public static final long CKM_SHA224_HMAC           =    0x00000256L;
    public static final long CKM_SHA224_HMAC_GENERAL   =    0x00000257L;
    public static final long CKM_SHA384                =    0x00000260L;
    public static final long CKM_SHA384_HMAC           =    0x00000261L;
    public static final long CKM_SHA384_HMAC_GENERAL   =    0x00000262L;
    public static final long CKM_SHA512                =    0x00000270L;
    public static final long CKM_SHA512_HMAC           =    0x00000271L;
    public static final long CKM_SHA512_HMAC_GENERAL   =    0x00000272L;

    public static final long CKM_EC_KEY_PAIR_GEN       =    0x00001040L;

    public static final long CKM_ECDSA                 =    0x00001041L;
    public static final long CKM_ECDSA_SHA1            =    0x00001042L;
    public static final long CKM_ECDSA_SHA224          =    0x00001043L;
    public static final long CKM_ECDSA_SHA256          =    0x00001044L;
    public static final long CKM_ECDSA_SHA384          =    0x00001045L;
    public static final long CKM_ECDSA_SHA512          =    0x00001046L;

    public static final long CKM_ECDH1_DERIVE          =    0x00001050L;

    public static final long CKM_AES_KEY_GEN           =    0x00001080L;
    public static final long CKM_AES_ECB               =    0x00001081L;
    public static final long CKM_AES_CBC               =    0x00001082L;
    public static final long CKM_AES_MAC               =    0x00001083L;
    public static final long CKM_AES_CBC_PAD           =    0x00001085L;
    public static final long CKM_AES_CTR               =    0x00001086L;
    public static final long CKM_AES_GCM               =    0x00001087L;
    public static final long CKM_AES_CCM               =    0x00001088L;
    public static final long CKM_AES_CTS               =    0x00001089L;
    public static final long CKM_AES_CMAC              =    0x0000108AL;

    public static final long CKM_DES_ECB_ENCRYPT_DATA  =    0x00001100L;
    public static final long CKM_DES_CBC_ENCRYPT_DATA  =    0x00001101L;
    public static final long CKM_DES3_ECB_ENCRYPT_DATA =    0x00001102L;
    public static final long CKM_DES3_CBC_ENCRYPT_DATA =    0x00001103L;
    public static final long CKM_AES_ECB_ENCRYPT_DATA  =    0x00001104L;
    public static final long CKM_AES_CBC_ENCRYPT_DATA  =    0x00001105L;

    public static final long CKM_DSA_PARAMETER_GEN     =    0x00002000L;
    public static final long CKM_DH_PKCS_PARAMETER_GEN =    0x00002001L;

    public static final long CKM_AES_KEY_WRAP          =    0x00002109L;     /* WAS: 0x00001090 */
    public static final long CKM_AES_KEY_WRAP_PAD      =    0x0000210AL;     /* WAS: 0x00001091 */

    public static final long CKM_VENDOR_DEFINED        =    0x80000000L;

    public NativeLong mechanism;

    public Pointer pParameter;

    public NativeLong ulParameterLen;  /* in bytes */

    public static CKMechanism create(long mechanism,Pointer param,long paramLen) {
        CKMechanism mech = new CKMechanism();
        mech.mechanism = new NativeLong(mechanism);
        mech.pParameter = param;
        mech.ulParameterLen = new NativeLong(paramLen);
        return mech;
    }
}
