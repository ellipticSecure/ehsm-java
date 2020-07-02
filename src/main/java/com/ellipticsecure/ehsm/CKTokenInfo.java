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
 * This is the CK_TOKEN_INFO structure.
 * @author Kobus Grobler
 */
@ToString
@Structure.FieldOrder({"label","manufacturerID","model","serialNumber","flags","ulMaxSessionCount",
        "ulSessionCount","ulMaxRwSessionCount","ulRwSessionCount","ulMaxPinLen","ulMinPinLen",
        "ulTotalPublicMemory","ulFreePublicMemory","ulTotalPrivateMemory","ulFreePrivateMemory",
        "hardwareVersion","firmwareVersion","utcTime"})
public class CKTokenInfo extends Structure {

    public final byte[] label = new byte[32];

    public final String getLabel() {
        return new String(label,0,label.length).trim();
    }

    public final byte[] manufacturerID = new byte[32];

    public final String getManufacturerID() {
        return new String(manufacturerID,0,manufacturerID.length).trim();
    }

    public final byte[] model = new byte[16];

    public final String getModel() {
        return new String(model,0,model.length).trim();
    }

    public final byte[] serialNumber = new byte[16];

    public final String getSerialNumber() {
        return new String(serialNumber,0,serialNumber.length).trim();
    }

    public NativeLong flags;

    public NativeLong ulMaxSessionCount;

    public NativeLong ulSessionCount;

    public NativeLong ulMaxRwSessionCount;

    public NativeLong ulRwSessionCount;

    public NativeLong ulMaxPinLen;

    public NativeLong ulMinPinLen;

    public NativeLong ulTotalPublicMemory;

    public NativeLong ulFreePublicMemory;

    public NativeLong ulTotalPrivateMemory;

    public NativeLong ulFreePrivateMemory;

    public CKVersion hardwareVersion;

    public CKVersion firmwareVersion;

    public final byte[] utcTime = new byte[16];
    public final String getUtcTime() {
        return new String(utcTime,0,utcTime.length).trim();
    }

}
