/*
 * Joshua Liu
 * Not quite working yet
 */

package org.ok.protocols;

public class HKDF {
    HMAC hmac;

    public HKDF() {
        hmac = new HMAC();
    }

    int[] hkdfExtract(int[] salt, int[] ikm) {
        if (salt.length == 0)
            salt = new int[hmac.sha.sha256(salt, ikm).length];
        return hmac.sha.sha256(salt, ikm);
    }

    int[] hkdfExpand(int[] prk, int[] info, int length) {
        int[] t = new int[0];
        int[] okm = new int[0];
        int i = 0;

        while (okm.length < length) {
            i++;
            t = hmac.sha.sha256(prk, concat(t, info, new int[] { i & 0xFF }));
            okm = concat(okm, t);
        }
        int[] result = new int[length];
        System.arraycopy(okm, 0, result, 0, length);
        return result;
    }

    int[] concat(int[]... arrays) {
        int totalLength = 0;
        for (int[] array : arrays) {
            totalLength += array.length;
        }
        int[] result = new int[totalLength];
        int currentIndex = 0;
        for (int[] array : arrays) {
            System.arraycopy(array, 0, result, currentIndex, array.length);
            currentIndex += array.length;
        }
        return result;
    }

    public int[] hkdf(int[] salt, int[] ikm, int[] info, int length) {
        int[] prk = hkdfExtract(salt, ikm);
        return hkdfExpand(prk, info, length);
    }

}
