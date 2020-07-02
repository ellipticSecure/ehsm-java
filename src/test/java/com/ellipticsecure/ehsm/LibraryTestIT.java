/*
 * Copyright (c) 2020 Elliptic
 *
 *  All rights reserved.
 *
 *  You may only use this code under the terms of the Elliptic license.
 *
 */

package com.ellipticsecure.ehsm;

import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.NativeLongByReference;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.bind.DatatypeConverter;

import static com.ellipticsecure.ehsm.CKFlags.*;
import static com.ellipticsecure.ehsm.CKReturnValues.*;
import static com.ellipticsecure.ehsm.CKUserTypes.CKU_SO;
import static com.ellipticsecure.ehsm.CKUserTypes.CKU_USER;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.fail;

/**
 * Integration Test for the eHSM library.
 * NOTE: !!! This test will destroy key material on the connected device !!!
 *
 * @author Kobus Grobler
 */
public class LibraryTestIT {
    private static final Logger logger = LoggerFactory.getLogger(LibraryTestIT.class);

    private static final String TEST_PIN = "testsu";
    private static final String TEST_SO_PIN = "testso";

    private static EHSMLibrary lib;

    private NativeLong slot;

    @BeforeClass
    public static void setupClass() {
        lib = Native.load(EHSMLibrary.getDefaultLibraryName(), EHSMLibrary.class);
    }

    @Before
    public void setup() {
        lib.C_Finalize(Pointer.NULL);
        long r = lib.C_Initialize(Pointer.NULL);
        assertEquals("C_Initialize returned 0x" + Long.toHexString(r), CKR_OK, r);
        slot = getPresentSlot();
        CKTokenInfo info = new CKTokenInfo();
        r = lib.C_GetTokenInfo(slot, info);
        assertEquals("C_GetTokenInfo returned 0x" + Long.toHexString(r), CKR_OK, r);
        if ((info.flags.longValue() & CKF_TOKEN_INITIALIZED) == 0) {
            logger.info("Device not initialized yet, doing it now.");

            r = lib.C_InitToken(slot,TEST_SO_PIN,new NativeLong(TEST_SO_PIN.length()),
                    String.format("%1$-32s", "testtoken"));
            assertEquals("C_InitToken returned 0x" + Long.toHexString(r), CKR_OK, r);
        }

        if ((info.flags.longValue() & CKF_USER_PIN_INITIALIZED) == 0) {
            logger.info("Device has no PIN set, doing it now.");
            NativeLong session = getLoggedInSession(slot, 6, CKU_SO, TEST_SO_PIN);
            r = lib.C_InitPIN(session, TEST_PIN, new NativeLong(TEST_PIN.length()));
            assertEquals("C_InitPIN returned 0x" + Long.toHexString(r), r, CKR_OK);
            lib.C_CloseSession(session);
        }
    }

    @After
    public void tearDown() {
        lib.C_Finalize(Pointer.NULL);
    }

    private NativeLong getPresentSlot() {
        NativeLong[] pSlotList = new NativeLong[10];
        NativeLongByReference pCount = new NativeLongByReference(new NativeLong(pSlotList.length));
        long r = lib.C_GetSlotList((byte) 1, pSlotList, pCount);
        assertEquals("C_GetSlotList returned 0x" + Long.toHexString(r), CKR_OK, r);

        if (pCount.getValue().longValue() == 0) {
            fail("No available slots found.");
        }
        return pSlotList[0];
    }

    private NativeLong getLoggedInSession(NativeLong slot, long type, long user, String pin) {
        NativeLongByReference pSession = new NativeLongByReference();
        // rw session
        long r = lib.C_OpenSession(slot, new NativeLong(type), Pointer.NULL, Pointer.NULL, pSession);
        assertEquals("Failed to create session: 0x" + Long.toHexString(r), CKR_OK, r);
        r = lib.C_Login(pSession.getValue(), new NativeLong(user), pin, new NativeLong(pin.length()));
        assertEquals("Failed to log in: 0x" + Long.toHexString(r), CKR_OK, r);
        return pSession.getValue();
    }

    @Test
    public void tokenInfo() {
        logger.info("token info test.");
        CKTokenInfo info = new CKTokenInfo();
        long r = lib.C_GetTokenInfo(slot, info);
        assertEquals("C_GetTokenInfo returned 0x" + Long.toHexString(r), CKR_OK, r);
        logger.info("Token info:{}", info);
        assertEquals("Manufacturer ID is invalid.",
                "ellipticSecure", info.getManufacturerID());
    }

    @Test
    public void configTest() {
        logger.info("config test.");
        EHSMConfig config = new EHSMConfig();
        long r = lib.u32GetTokenConfig(slot,config);
        assertEquals("u32GetTokenConfig returned 0x" + Long.toHexString(r), CKR_OK, r);
        logger.info("Config: {}",config);

        NativeLong session = getLoggedInSession(slot,CKF_RW_SESSION | CKF_SERIAL_SESSION, CKU_SO, TEST_SO_PIN);

        short options =  config.u16BitOptions;
        byte sessionTimeout = config.u8SessionTimeout;

        r = lib.u32SetBitOptions(slot,(short)0);
        assertEquals("u32SetBitOptions returned 0x" + Long.toHexString(r), CKR_OK, r);

        r = lib.u32SetSessionTimeout(slot,(byte)10);
        assertEquals("u32SetSessionTimeout returned 0x" + Long.toHexString(r), CKR_OK, r);

        r = lib.u32GetTokenConfig(slot,config);
        assertEquals("u32GetTokenConfig returned 0x" + Long.toHexString(r), CKR_OK, r);
        logger.info("Config: {}",config);
        assertEquals("u32GetTokenConfig expected 0 for options but got 0x" + Long.toHexString(config.u16BitOptions), 0, config.u16BitOptions);
        assertEquals("u32GetTokenConfig expected 0 for timeout but got 0x" + Long.toHexString(config.u8SessionTimeout), 10, config.u8SessionTimeout);

        // set original value
        r = lib.u32SetBitOptions(slot,options);
        assertEquals("u32SetBitOptions returned 0x" + Long.toHexString(r), CKR_OK, r);
        r = lib.u32SetSessionTimeout(slot,sessionTimeout);
        assertEquals("u32SetSessionTimeout returned 0x" + Long.toHexString(r), CKR_OK, r);

        lib.C_CloseSession(session);

    }

    @Test
    public void factoryReset() {
        logger.info("Factory reset test.");
        long r = lib.u32FactoryReset(slot);
        // should return CKR_ACTION_PROHIBITED unless button is pressed during test
        assertEquals("u32FactoryReset returned 0x" + Long.toHexString(r), r, CKR_ACTION_PROHIBITED);
    }

    @Test
    public void initPinTest() {
        logger.info("Performing PIN test.");

        NativeLong session = getLoggedInSession(slot, CKF_RW_SESSION | CKF_SERIAL_SESSION, CKU_SO, TEST_SO_PIN);
        String newSuPin = "newsupin";
        long r = lib.C_InitPIN(session, newSuPin, new NativeLong(newSuPin.length()));
        assertEquals("C_InitPIN returned 0x" + Long.toHexString(r), r, CKR_OK);

        r = lib.C_CloseSession(session);
        assertEquals("C_CloseSession returned 0x" + Long.toHexString(r), r, CKR_OK);

        session = getLoggedInSession(slot, CKF_RW_SESSION | CKF_SERIAL_SESSION, CKU_USER, newSuPin);

        // revert back so other tests dont fail
        r = lib.C_InitPIN(session, TEST_PIN, new NativeLong(TEST_PIN.length()));
        assertEquals("C_InitPIN returned 0x" + Long.toHexString(r), r, CKR_OK);
    }

    @Test
    public void btcTest() {
        logger.info("Performing btc test.");

        NativeLong session = getLoggedInSession(slot, CKF_RW_SESSION | CKF_SERIAL_SESSION, CKU_USER, TEST_PIN);

        NativeLongByReference pBTCHandle = new NativeLongByReference();
        long r = lib.u32HasBitcoinKey(session, pBTCHandle);
        if (r == CKR_OK) {
            logger.info("deleting btc key.");
            r = lib.C_DestroyObject(session, pBTCHandle.getValue());
            assertEquals(r, CKR_OK);
            r = lib.u32HasBitcoinKey(session, pBTCHandle);
            assertEquals(r, BTC_KEY_NOT_FOUND);
        } else if (r == BTC_KEY_NOT_FOUND) {
            // OK.
            logger.debug("btc key not found.");
        } else {
            fail("Failed to get btc key: 0x" + Long.toHexString(r));
        }

        byte[] key = DatatypeConverter.parseHexBinary("000102030405060708090a0b0c0d0e0f");
        r = lib.u32ImportBitcoinKey(session, key, new NativeLong(key.length));
        assertEquals("Failed to import btc key: 0x" + Long.toHexString(r), r, CKR_OK);


        // perform BIP32 tests from test vectors defined in https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

        int net = 0x0488B21E; // main net
        int[] indexes = {};
        String xpub = EHSMLibrary.GetBIP32XPub(lib,session,net,indexes);
        assertEquals("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
                xpub);

        indexes = new int[]{0x80000000};
        xpub = EHSMLibrary.GetBIP32XPub(lib,session,net,indexes);
        assertEquals("xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",xpub);

        indexes = new int[]{0x80000000,1};
        xpub = EHSMLibrary.GetBIP32XPub(lib,session,net,indexes);
        assertEquals("xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",xpub);

        indexes = new int[]{0x80000000,1,0x80000002};
        xpub = EHSMLibrary.GetBIP32XPub(lib,session,net,indexes);
        assertEquals("xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",xpub);

        indexes = new int[]{0x80000000,1,0x80000002, 2};
        xpub = EHSMLibrary.GetBIP32XPub(lib,session,net,indexes);
        assertEquals("xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",xpub);

        indexes = new int[]{0x80000000,1,0x80000002, 2, 1000000000};
        xpub = EHSMLibrary.GetBIP32XPub(lib,session,net,indexes);
        assertEquals("xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",xpub);
    }
}
