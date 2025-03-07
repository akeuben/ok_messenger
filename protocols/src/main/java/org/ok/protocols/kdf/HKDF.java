package org.ok.protocols.kdf;
/*
 * Joshua Liu
 * HKDF implementation
*/

import org.ok.protocols.Block;
import org.ok.protocols.hmacsha256.HMAC;

public class HKDF {

    private byte[] hmacDigest(byte[] key, byte[] data) {
        Block result = new HMAC().encode(new Block(key.length, key), new Block(data.length, data));
        byte[] res = new byte[result.getSizeBytes()];
        for (int i = 0; i < res.length; i++) {
            res[i] = result.getData()[i];
        }
        return res;
    }

    private byte[] hkdfExtract(byte[] salt, byte[] ikm) {
        if (salt.length == 0) {
            salt = new byte[32];
        }
        return hmacDigest(salt, ikm);
    }

    private byte[] hkdfExpand(byte[] prk, byte[] info, int length) {
        byte[] t = new byte[0];
        byte[] okm = new byte[0];
        int i = 0;
        while (okm.length < length) {
            i++;
            t = hmacDigest(prk, concat(t, info, new byte[] { (byte) i }));

            okm = concat(okm, t);
        }
        byte[] result = new byte[length];
        System.arraycopy(okm, 0, result, 0, length);
        return result;
    }

    public Block hkdf(Block salt, Block ikm, Block info, int length) {
        byte[] prk = hkdfExtract(salt.getData(), ikm.getData());
        byte[] temp = hkdfExpand(prk, info.getData(), length);
        return new Block(temp.length, temp);
    }

    private byte[] concat(byte[]... arrays) {
        int totalLength = 0;
        for (byte[] array : arrays) {
            totalLength += array.length;
        }
        byte[] result = new byte[totalLength];
        int currentIndex = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, currentIndex, array.length);
            currentIndex += array.length;
        }
        return result;
    }
}
