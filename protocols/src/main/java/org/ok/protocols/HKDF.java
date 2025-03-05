package org.ok.protocols;
/*
 * Joshua Liu
 * Not quite working yet
*/

public class HKDF {

    public  byte[] hmacDigest(byte[] key, byte[] data) {
        int[] keyI = new int[key.length];
        for (int i = 0; i < keyI.length; i++) {
            keyI[i] = key[i];
        }
        int[] dataI = new int[data.length];
        for (int i = 0; i < dataI.length; i++) {
            dataI[i] = data[i];
        }
        int[] result = new HMAC().hmac_sha256(keyI, (long) keyI.length, dataI, (long) dataI.length, new int[32], 32);
        byte[] res = new byte[result.length];
        for (int i = 0; i < result.length; i++) {
            res[i] = (byte) (result[i] & 0xFF);
        }
        return res;
    }

    public  byte[] hkdfExtract(byte[] salt, byte[] ikm) {
        if (salt.length == 0) {
            salt = new byte[32];
        }

        return hmacDigest(salt, ikm);
    }

    public  byte[] hkdfExpand(byte[] prk, byte[] info, int length) {
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

    public  byte[] hkdf(byte[] salt, byte[] ikm, byte[] info, int length) {
        byte[] prk = hkdfExtract(salt, ikm);
        return hkdfExpand(prk, info, length);
    }

    private  byte[] concat(byte[]... arrays) {
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

    // public static void main(String[] args) throws Exception {
    //     byte[] okm = hkdf(
    //             "t".getBytes("UTF-8"),
    //             "hello".getBytes("UTF-8"),
    //             "t".getBytes("UTF-8"),
    //             32);
    //     for (byte i : okm) {
    //         System.out.printf("%02x", i);
    //     }
    // }
}
