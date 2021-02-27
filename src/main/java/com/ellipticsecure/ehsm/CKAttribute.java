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
import com.sun.jna.Structure;
import com.sun.jna.ptr.ByteByReference;
import com.sun.jna.ptr.NativeLongByReference;
import lombok.ToString;

/**
 * This is the CK_ATTRIBUTE structure.
 *
 * @author Kobus Grobler
 */
@ToString
@Structure.FieldOrder({"type", "pValue", "ulValueLen"})
public class CKAttribute extends Structure {

    public static final long CKF_ARRAY_ATTRIBUTE = 0x40000000L;
    public static final long CKA_CLASS = 0x00000000L;
    public static final long CKA_TOKEN = 0x00000001L;
    public static final long CKA_PRIVATE = 0x00000002L;
    public static final long CKA_LABEL = 0x00000003L;
    public static final long CKA_APPLICATION = 0x00000010L;
    public static final long CKA_VALUE = 0x00000011L;
    public static final long CKA_OBJECT_ID = 0x00000012L;
    public static final long CKA_CERTIFICATE_TYPE = 0x00000080L;
    public static final long CKA_ISSUER = 0x00000081L;
    public static final long CKA_SERIAL_NUMBER = 0x00000082L;
    public static final long CKA_AC_ISSUER = 0x00000083L;
    public static final long CKA_OWNER = 0x00000084L;
    public static final long CKA_ATTR_TYPES = 0x00000085L;
    public static final long CKA_TRUSTED = 0x00000086L;
    public static final long CKA_CERTIFICATE_CATEGORY = 0x00000087L;
    public static final long CKA_JAVA_MIDP_SECURITY_DOMAIN = 0x00000088L;
    public static final long CKA_URL = 0x00000089L;
    public static final long CKA_HASH_OF_SUBJECT_PUBLIC_KEY = 0x0000008AL;
    public static final long CKA_HASH_OF_ISSUER_PUBLIC_KEY = 0x0000008BL;
    public static final long CKA_NAME_HASH_ALGORITHM = 0x0000008CL;
    public static final long CKA_CHECK_VALUE = 0x00000090L;

    public static final long CKA_KEY_TYPE = 0x00000100L;
    public static final long CKA_SUBJECT = 0x00000101L;
    public static final long CKA_ID = 0x00000102L;
    public static final long CKA_SENSITIVE = 0x00000103L;
    public static final long CKA_ENCRYPT = 0x00000104L;
    public static final long CKA_DECRYPT = 0x00000105L;
    public static final long CKA_WRAP = 0x00000106L;
    public static final long CKA_UNWRAP = 0x00000107L;
    public static final long CKA_SIGN = 0x00000108L;
    public static final long CKA_SIGN_RECOVER = 0x00000109L;
    public static final long CKA_VERIFY = 0x0000010AL;
    public static final long CKA_VERIFY_RECOVER = 0x0000010BL;
    public static final long CKA_DERIVE = 0x0000010CL;
    public static final long CKA_START_DATE = 0x00000110L;
    public static final long CKA_END_DATE = 0x00000111L;
    public static final long CKA_MODLUS = 0x00000120L;
    public static final long CKA_MODLUS_BITS = 0x00000121L;
    public static final long CKA_PUBLIC_EXPONENT = 0x00000122L;
    public static final long CKA_PRIVATE_EXPONENT = 0x00000123L;
    public static final long CKA_PRIME_1 = 0x00000124L;
    public static final long CKA_PRIME_2 = 0x00000125L;
    public static final long CKA_EXPONENT_1 = 0x00000126L;
    public static final long CKA_EXPONENT_2 = 0x00000127L;
    public static final long CKA_COEFFICIENT = 0x00000128L;
    public static final long CKA_PUBLIC_KEY_INFO = 0x00000129L;
    public static final long CKA_PRIME = 0x00000130L;
    public static final long CKA_SUBPRIME = 0x00000131L;
    public static final long CKA_BASE = 0x00000132L;

    public static final long CKA_PRIME_BITS = 0x00000133L;
    public static final long CKA_SUBPRIME_BITS = 0x00000134L;
    public static final long CKA_SUB_PRIME_BITS = CKA_SUBPRIME_BITS;

    public static final long CKA_VALUE_BITS = 0x00000160L;
    public static final long CKA_VALUE_LEN = 0x00000161L;
    public static final long CKA_EXTRACTABLE = 0x00000162L;
    public static final long CKA_LOCAL = 0x00000163L;
    public static final long CKA_NEVER_EXTRACTABLE = 0x00000164L;
    public static final long CKA_ALWAYS_SENSITIVE = 0x00000165L;
    public static final long CKA_KEY_GEN_MECHANISM = 0x00000166L;

    public static final long CKA_MODIFIABLE = 0x00000170L;
    public static final long CKA_COPYABLE = 0x00000171L;

    public static final long CKA_DESTROYABLE = 0x00000172L;

    public static final long CKA_ECDSA_PARAMS = 0x00000180L; /* Deprecated */
    public static final long CKA_EC_PARAMS = 0x00000180L;

    public static final long CKA_EC_POINT = 0x00000181L;

    public static final long CKA_SECONDARY_AUTH = 0x00000200L; /* Deprecated */
    public static final long CKA_AUTH_PIN_FLAGS = 0x00000201L; /* Deprecated */

    public static final long CKA_ALWAYS_AUTHENTICATE = 0x00000202L;

    public static final long CKA_WRAP_WITH_TRUSTED = 0x00000210L;
    public static final long CKA_WRAP_TEMPLATE = (CKF_ARRAY_ATTRIBUTE | 0x00000211L);
    public static final long CKA_UNWRAP_TEMPLATE = (CKF_ARRAY_ATTRIBUTE | 0x00000212L);
    public static final long CKA_DERIVE_TEMPLATE = (CKF_ARRAY_ATTRIBUTE | 0x00000213L);

    public static final long CKA_OTP_FORMAT = 0x00000220L;
    public static final long CKA_OTP_LENGTH = 0x00000221L;
    public static final long CKA_OTP_TIME_INTERVAL = 0x00000222L;
    public static final long CKA_OTP_USER_FRIENDLY_MODE = 0x00000223L;
    public static final long CKA_OTP_CHALLENGE_REQUIREMENT = 0x00000224L;
    public static final long CKA_OTP_TIME_REQUIREMENT = 0x00000225L;
    public static final long CKA_OTP_COUNTER_REQUIREMENT = 0x00000226L;
    public static final long CKA_OTP_PIN_REQUIREMENT = 0x00000227L;
    public static final long CKA_OTP_COUNTER = 0x0000022FL;
    public static final long CKA_OTP_USER_IDENTIFIER = 0x0000022AL;
    public static final long CKA_OTP_SERVICE_IDENTIFIER = 0x0000022BL;
    public static final long CKA_OTP_SERVICE_LOGO = 0x0000022CL;
    public static final long CKA_OTP_SERVICE_LOGO_TYPE = 0x0000022DL;

    public static final long CKA_GOSTR3410_PARAMS = 0x00000250L;
    public static final long CKA_GOSTR3411_PARAMS = 0x00000251L;
    public static final long CKA_GOST28147_PARAMS = 0x00000252L;

    public static final long CKA_HW_FEATURE_TYPE = 0x00000300L;
    public static final long CKA_RESET_ON_INIT = 0x00000301L;
    public static final long CKA_HAS_RESET = 0x00000302L;

    public static final long CKA_PIXEL_X = 0x00000400L;
    public static final long CKA_PIXEL_Y = 0x00000401L;
    public static final long CKA_RESOLUTION = 0x00000402L;
    public static final long CKA_CHAR_ROWS = 0x00000403L;
    public static final long CKA_CHAR_COLUMNS = 0x00000404L;
    public static final long CKA_COLOR = 0x00000405L;
    public static final long CKA_BITS_PER_PIXEL = 0x00000406L;
    public static final long CKA_CHAR_SETS = 0x00000480L;
    public static final long CKA_ENCODING_METHODS = 0x00000481L;
    public static final long CKA_MIME_TYPES = 0x00000482L;
    public static final long CKA_MECHANISM_TYPE = 0x00000500L;
    public static final long CKA_REQUIRED_CMS_ATTRIBUTES = 0x00000501L;
    public static final long CKA_DEFAULT_CMS_ATTRIBUTES = 0x00000502L;
    public static final long CKA_SUPPORTED_CMS_ATTRIBUTES = 0x00000503L;
    public static final long CKA_ALLOWED_MECHANISMS = (CKF_ARRAY_ATTRIBUTE | 0x00000600L);
    public static final long CKA_VENDOR_DEFINED = 0x80000000L;
    public static final long CKA_BTC_CHAIN = CKA_VENDOR_DEFINED + 1;
    public static final long CKA_PIV_CERT = CKA_BTC_CHAIN + 1;

    // CKA_CERTIFICATE_TYPE attribute types
    public static final long CKC_X_509 = 0x00000000L;
    public static final long CKC_X_509_ATTR_CERT = 0x00000001L;
    public static final long CKC_WTLS = 0x00000002L;
    public static final long CKC_VENDOR_DEFINED = 0x80000000L;
    public static final long CKC_OPENPGP = (CKC_VENDOR_DEFINED | 0x00504750);

    // CK_ATTRIBUTE_TYPE type
    public NativeLong type;
    // CK_VOID_PTR       pValue
    public Pointer pValue;
    // CK_ULONG          ulValueLen
    public NativeLong ulValueLen;

    public static CKAttribute setLongAttribute(CKAttribute attribute,long type,long val) {
        attribute.type = new NativeLong(type);
        NativeLongByReference value = new NativeLongByReference(new NativeLong(val));
        attribute.pValue = value.getPointer();
        attribute.ulValueLen = new NativeLong(NativeLong.SIZE);
        return attribute;
    }

    public static Memory getFromBytes(byte[] val) {
        Memory mem = new Memory(val.length);
        mem.write(0, val, 0, val.length);
        return mem;
    }

    public static CKAttribute setBytesAttribute(CKAttribute attribute,long type,Memory val) {
        attribute.type = new NativeLong(type);
        attribute.pValue = val;
        attribute.ulValueLen = new NativeLong(val.size());
        return attribute;
    }

    public static CKAttribute setBoolAttribute(CKAttribute attribute, long type, boolean val) {
        attribute.type = new NativeLong(type);
        ByteByReference boolVal;
        if (val) {
            boolVal = new ByteByReference((byte)1);
        } else {
            boolVal = new ByteByReference((byte)0);
        }
        attribute.pValue = boolVal.getPointer();
        attribute.ulValueLen = new NativeLong(1);
        return attribute;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;

        CKAttribute that = (CKAttribute) o;

        if (!type.equals(that.type)) return false;
        if (!pValue.equals(that.pValue)) return false;
        return ulValueLen.equals(that.ulValueLen);
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + type.hashCode();
        result = 31 * result + pValue.hashCode();
        result = 31 * result + ulValueLen.hashCode();
        return result;
    }
}
