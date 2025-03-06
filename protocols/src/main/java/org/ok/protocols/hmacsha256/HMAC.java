package org.ok.protocols.hmacsha256;

import org.ok.protocols.Block;

public class HMAC {

    protected final int SHA256_HASH_SIZE = 32;
    protected final int BLOCK_SIZE = 64;

    protected SHA256 sha;

    public HMAC() {
        sha = new SHA256();
    }

    Block hmac_sha256(Block key, Block data) {
        int[] k = new int[BLOCK_SIZE];
        int[] k_ipad = new int[BLOCK_SIZE];
        int[] k_opad = new int[BLOCK_SIZE];
        Block ihash = new Block(SHA256_HASH_SIZE);
        Block ohash = new Block(SHA256_HASH_SIZE);
        int keylen = key.getSizeBytes();
        int datalen = data.getSizeBytes();
        int i;
        for (i = 0; i < k.length; i++) {
            k[i] = 0;
        }
        for (i = 0; i < BLOCK_SIZE; i++) {
            k_ipad[i] = 0x36;
        }
        for (i = 0; i < BLOCK_SIZE; i++) {
            k_opad[i] = 0x5c;
        }

        if (keylen > BLOCK_SIZE) {
            // If the key is larger than the hash algorithm's
            // block size, we must digest it first.
            Block out = sha.sha256(key);
        } else {
            for (i = 0; i < keylen; i++) {
                k[i] = (byte) key.getData()[i];
            }
        }

        for (i = 0; i < BLOCK_SIZE; i++) {
            k_ipad[i] ^= k[i];
            k_opad[i] ^= k[i];
        }

        // Perform HMAC algorithm: ( https://tools.ietf.org/html/rfc2104 )
        // `H(K XOR opad, H(K XOR ipad, data))`
        ihash = H(k_ipad, k_ipad.length, data, datalen, ihash.getSizeBytes());
        ohash = H(k_opad, k_opad.length, ihash, ihash.getSizeBytes(), ohash.getSizeBytes());

        return ohash;
    }

    Block H(int[] x, long xlen, Block y, long ylen, long outlen) {
        long buflen = (xlen + ylen);
        int[] buf = new int[(int) buflen];

        for (int i = 0; i < xlen; i++) {
            buf[i] = x[i];
        }
        for (int i = 0; i < ylen; i++) {
            buf[i + (int) xlen] = y.getData()[i];
        }
        byte[] buffer = new byte[buf.length];
        for (int i = 0; i < buffer.length; i++) {
            buffer[i] = (byte) (buf[i] & 0xFF);
        }
        return sha.sha256(new Block(buffer.length, buffer));
    }

    public Block encode(Block value, Block key) {
        return hmac_sha256(key, value);
    }
}
