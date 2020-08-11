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
 * A runtime exception that contains the CKR code returned by a function.
 * @author Kobus Grobler
 */
public class EHSMException extends RuntimeException {

    private static final long serialVersionUID = -7575689600382949310L;

    private final long code;

    /**
     * Creates a new EHSMException
     * @param message the related error message
     * @param code the CK_xx error code that caused the exception
     */
    public EHSMException(String message, long code) {
        super(message);
        this.code = code;
    }

    /**
     * Retrieves the CKR_xx error code that was supplied to the constructor
     * @return the error code
     */
    public long getCode() { return code; }
}
