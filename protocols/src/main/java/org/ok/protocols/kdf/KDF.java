package org.ok.protocols.kdf;

import org.ok.protocols.Block;
import org.ok.protocols.hmacsha256.HMAC;

/*
 * Joshua Liu
 * KDF_RF & KDF_CK
 * KDF_RK(rk, dh_out): Returns a pair (32-byte root key, 32-byte chain key) as the output of applying a KDF keyed by a 32-byte root key rk to a Diffie-Hellman output dh_out.

KDF_CK(ck): Returns a pair (32-byte chain key, 32-byte message key) as the output of applying a KDF keyed by a 32-byte chain key ck to some constant.
 */

public class KDF {
    public KDF() {

    }

    public Block[]kdf_rk(Block rk, Block dhOut) {
        Block[] output = new Block[2];
        output[0] = new HKDF().hkdf(rk, dhOut, new Block(1,new byte[0]), 32);
        output[1] = new HKDF().hkdf(rk, dhOut, new Block(1,new byte[0]), 32);
        return output;
    }

    // Output is message key [0], then chain key [1]
    public Block[]kdf_ck(byte[] ck) {
        Block[] output = new Block[2];
        Block ckBlock = new Block(ck.length, ck);
        output[0] = new HMAC().encode(ckBlock, new Block(2, new byte[] { 0, 1 })); // message
        output[1] = new HMAC().encode(ckBlock, new Block(2, new byte[] { 0, 2 })); // key
        return output;
    }
}
