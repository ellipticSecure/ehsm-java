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
import com.sun.jna.ptr.NativeLongByReference;
import lombok.NonNull;

import java.io.Closeable;
import java.io.IOException;
import java.util.Iterator;
import java.util.NoSuchElementException;

import static com.ellipticsecure.ehsm.CKReturnValues.CKR_OK;

/**
 * This is a helper class to iterate over the security module objects. Use with try to ensure the
 * iterator is closed.
 *
 * @author Kobus Grobler
 */
public class ObjectHandleIterator implements Closeable, Iterator<NativeLong> {

    private static final NativeLong ONE = new NativeLong(1);

    private final EHSMLibrary lib;
    private final NativeLong session;

    private final NativeLongByReference objectHandle = new NativeLongByReference();
    private final NativeLongByReference count = new NativeLongByReference();

    public ObjectHandleIterator(@NonNull EHSMLibrary lib,@NonNull  NativeLong session,@NonNull CKAttribute []attributes) {
        this.lib = lib;
        this.session = session;

        EHSMLibrary.throwIfNotOK(lib.C_FindObjectsInit(session,attributes,new NativeLong(attributes.length)));
        long r = lib.C_FindObjects(session, objectHandle, ONE, count);
        if (r != CKR_OK) {
            lib.C_FindObjectsFinal(session);
            EHSMLibrary.throwIfNotOK(r);
        }
    }

    @Override
    public void close() throws IOException {
        long r = lib.C_FindObjectsFinal(session);
        if (r != CKR_OK) {
            throw new IOException(CKReturnValues.getErrorMessage(r));
        }
    }

    @Override
    public boolean hasNext() {
        return count.getValue().longValue() > 0;
    }

    @Override
    public NativeLong next() {
        if (!hasNext()) {
            throw new NoSuchElementException();
        }
        NativeLong objHandle = new NativeLong(objectHandle.getValue().longValue());
        EHSMLibrary.throwIfNotOK(lib.C_FindObjects(session, objectHandle, ONE, count));
        return objHandle;
    }
}
