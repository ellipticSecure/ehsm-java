/*
 * Copyright (c) 2020 Elliptic
 *
 *  All rights reserved.
 *
 *  You may only use this code under the terms of the Elliptic license.
 *
 */

package com.ellipticsecure.ehsm;

import com.sun.jna.Structure;
import lombok.Getter;
import lombok.ToString;

/**
 * This is the CK_VERSION structure.
 * @author Kobus Grobler
 */
@Getter
@ToString
@Structure.FieldOrder({"major","minor"})
public class CKVersion extends Structure {
    public byte major;
    public byte minor;
}
