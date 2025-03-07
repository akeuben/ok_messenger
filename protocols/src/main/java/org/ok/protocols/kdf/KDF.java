/*
 * Joshua Liu
 * KDF_RK and KDF_CK implementations from the Signal Docs
 */
package org.ok.protocols.kdf;

import org.ok.protocols.Block;
import org.ok.protocols.hmacsha256.HMAC;

public class KDF {
    public KDF() {

    }

    // Output is message key [0], then chain key [1]
    public Block[] kdf_rk(Block rk, Block dhOut) {
        Block[] output = new Block[2];
        output[0] = new HKDF().hkdf(rk, dhOut, new Block(1, new byte[0]), 32);
        output[1] = new HKDF().hkdf(rk, dhOut, new Block(1, new byte[0]), 32);
        return output;
    }

    // Output is message key [0], then chain key [1]
    public Block[] kdf_ck(byte[] ck) {
        Block[] output = new Block[2];
        Block ckBlock = new Block(ck.length, ck);
        output[0] = new HMAC().encode(ckBlock, new Block(2, new byte[] { 0, 1 })); // message
        output[1] = new HMAC().encode(ckBlock, new Block(2, new byte[] { 0, 2 })); // key
        return output;
    }
}
