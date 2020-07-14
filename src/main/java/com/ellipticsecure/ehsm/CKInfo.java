/*
 * Copyright (c) 2020 Elliptic
 *
 *  All rights reserved.
 *
 *  You may only use this code under the terms of the Elliptic license.
 *
 */

package com.ellipticsecure.ehsm;

import com.sun.jna.NativeLong;
import com.sun.jna.Structure;
import lombok.ToString;

/**
 * This is the CK_INFO structure.
 * @author Kobus Grobler
 */
@ToString
@Structure.FieldOrder({"cryptokiVersion","manufacturerID","flags","libraryDescription","libraryVersion"})
public class CKInfo extends Structure {
    // CK_VERSION    cryptokiVersion;     /* Cryptoki interface ver */
    public CKVersion cryptokiVersion;

    // CK_UTF8CHAR   manufacturerID[32];  /* blank padded */
    public final byte[] manufacturerID = new byte[32];

    public final String getManufacturerID() {
        return new String(manufacturerID,0,manufacturerID.length).trim();
    }

    // CK_FLAGS      flags;               /* must be zero */
    public NativeLong flags;

    // CK_UTF8CHAR   libraryDescription[32];  /* blank padded */
    public final byte[] libraryDescription = new byte[32];

    public final String getLibraryDescription() {
        return new String(libraryDescription,0,libraryDescription.length).trim();
    }

    // CK_VERSION    libraryVersion;          /* version of library */
    public CKVersion libraryVersion;

}
