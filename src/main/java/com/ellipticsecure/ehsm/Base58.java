/**
 * Copyright 2011 Google Inc.
 * Copyright (c) 2020 Elliptic
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.ellipticsecure.ehsm;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * A custom form of base58 is used to encode BitCoin addresses. Note that this is not the same base58 as used by
 * Flickr, which you may see reference to around the internet.<p>
 *
 * Satoshi says: why base-58 instead of standard base-64 encoding?<p>
 *
 * <ul>
 * <li>Don't want 0OIl characters that look the same in some fonts and
 *    could be used to create visually identical looking account numbers.</li>
 * <li>A string with non-alphanumeric characters is not as easily accepted as an account number.</li>
 * <li>E-mail usually won't line-break if there's no punctuation to break at.</li>
 * <li>Doubleclicking selects the whole number as one word if it's all alphanumeric.</li>
 * </ul>
 */
public class Base58 {
    private static final String ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final BigInteger BASE = BigInteger.valueOf(58);

    public static String encode(byte[] input) {
        // TODO: This could be a lot more efficient.
        BigInteger bi = new BigInteger(1, input);
        StringBuffer s = new StringBuffer();
        while (bi.compareTo(BASE) >= 0) {
            BigInteger mod = bi.mod(BASE);
            s.insert(0, ALPHABET.charAt(mod.intValue()));
            bi = bi.subtract(mod).divide(BASE);
        }
        s.insert(0, ALPHABET.charAt(bi.intValue()));
        // Convert leading zeros too.
        for (byte anInput : input) {
            if (anInput == 0)
                s.insert(0, ALPHABET.charAt(0));
            else
                break;
        }
        return s.toString();
    }

    /**
     * Encodes bytes as a base58 string. A checksum is appended.
     *
     * @param payload the bytes to encode, e.g. pubkey hash
     * @return the base58-encoded string
     */
    public static String encodeChecked(byte[] payload) {
        byte[] addressBytes = new byte[payload.length + 4];
        System.arraycopy(payload, 0, addressBytes, 0, payload.length);
        byte[] checksum = doubleDigest(addressBytes, 0, payload.length);
        System.arraycopy(checksum, 0, addressBytes, payload.length, 4);
        return encode(addressBytes);
    }

    public static byte[] doubleDigest(byte[] input, int offset, int length) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(input, offset, length);
            byte[] first = digest.digest();
            return digest.digest(first);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }
}
