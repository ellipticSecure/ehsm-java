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
 * Runtime exception that contains the CKR code returned by a function.
 * @author Kobus Grobler
 */
public class EHSMException extends RuntimeException {

    private static final long serialVersionUID = -7575689600382949310L;

    private long code;

    public EHSMException(String message, long code) {
        super(message);
        this.code = code;
    }

    public long getCode() { return code; }
}
