package org.ok.protocols;

/*
 * Joshua Liu
 * KDF_RF & KDF_CK
 * KDF_RK(rk, dh_out): Returns a pair (32-byte root key, 32-byte chain key) as the output of applying a KDF keyed by a 32-byte root key rk to a Diffie-Hellman output dh_out.

KDF_CK(ck): Returns a pair (32-byte chain key, 32-byte message key) as the output of applying a KDF keyed by a 32-byte chain key ck to some constant.
 */

public class KDF {
    public KDF() {

    }

    public byte[][] kdf_rf(byte[] rk, byte[] dhOut) {
        byte[][] output = new byte[2][0];
        output[0] = new HKDF().hkdf(rk, dhOut, new byte[0], 32);
        output[1] = new HKDF().hkdf(rk, dhOut, new byte[0], 32);
        return output;
    }

    // Output is message key [0], then chain key [1]
    public byte[][] kdf_ck(byte[] ck) {
        int[][] output = new int[2][32];
        int[] temp = new int[ck.length];
        for (int i = 0; i < temp.length; i++) {
            temp[i] = ck[i];
        }
        output[0] = new HMAC().hmac_sha256(temp, temp.length, new int[] { 0, 1 }, 2, output[0], 32);// message
        output[1] = new HMAC().hmac_sha256(temp, temp.length, new int[] { 0, 2 }, 2, output[1], 32);
        byte[][] tempO = new byte[2][0];
        tempO[0] = new byte[output[0].length];
        tempO[1] = new byte[output[1].length];
        for (int i = 0; i < 2; i++) {
            for (int j = 0; j < output[i].length; j++) {
                tempO[i][j] = (byte) (output[i][j] & 0xFF);
            }
        }
        return tempO;
    }
}
