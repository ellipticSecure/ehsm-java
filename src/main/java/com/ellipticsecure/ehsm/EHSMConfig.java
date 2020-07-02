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
 * This structure defines device specific configuration options.
 * @author Kobus Grobler
 */
@Getter
@ToString
@Structure.FieldOrder({"u8Version","u8Length","u8MaxUserFailCnt","u8MaxSOFailCnt",
        "u8SessionTimeout","u16BitOptions"})
public class EHSMConfig extends Structure {

    /**
     * The current configuration structure version.
     */
    public static final byte EHSM_CONFIG_VERSION = 1;

    //Note: BITS > 4 are reserved.
    public static final int BIT_OPTS_REQ_BTN_ON_BACKUP = 1;
    public static final int BIT_OPTS_ENABLE_CTAP2 = 2;
    public static final int BIT_OPTS_ENABLE_U2F = 4;

    public EHSMConfig() {
        u8Version = EHSM_CONFIG_VERSION;
        u8Length = 8;
    }

    public byte u8Version;
    public byte u8Length;
    public byte u8MaxUserFailCnt;
    public byte u8MaxSOFailCnt;
    public byte u8SessionTimeout;
    public short u16BitOptions;
}
