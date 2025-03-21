/*
 * Joshua Liu
 * HMAC implementation that calls SHA256 implementation
 */
package org.ok.protocols.hmacsha256;

import org.ok.protocols.Block;

public class HMAC {

    private final int SHA256_HASH_SIZE = 32;
    private final int BLOCK_SIZE = 64;

    private Block hmacSha256(Block key, Block data) {
        int[] k = new int[BLOCK_SIZE];
        int[] kIpad = new int[BLOCK_SIZE];
        int[] kOpad = new int[BLOCK_SIZE];
        Block ihash = new Block(SHA256_HASH_SIZE);
        Block ohash = new Block(SHA256_HASH_SIZE);
        int keylen = key.getSizeBytes();
        int datalen = data.getSizeBytes();
        int i;
        for (i = 0; i < k.length; i++) {
            k[i] = 0;
        }
        for (i = 0; i < BLOCK_SIZE; i++) {
            kIpad[i] = 0x36;
        }
        for (i = 0; i < BLOCK_SIZE; i++) {
            kOpad[i] = 0x5c;
        }

        if (keylen > BLOCK_SIZE) {
            // If the key is larger than the hash algorithm's
            // block size, we must digest it first.
            Block out = SHA256.sha256(key);
        } else {
            for (i = 0; i < keylen; i++) {
                k[i] = (byte) key.getData()[i];
            }
        }

        for (i = 0; i < BLOCK_SIZE; i++) {
            kIpad[i] ^= k[i];
            kOpad[i] ^= k[i];
        }

        // Perform HMAC algorithm: ( https://tools.ietf.org/html/rfc2104 )
        // `H(K XOR opad, H(K XOR ipad, data))`
        ihash = H(kIpad, kIpad.length, data, datalen, ihash.getSizeBytes());
        ohash = H(kOpad, kOpad.length, ihash, ihash.getSizeBytes(), ohash.getSizeBytes());

        return ohash;
    }

    private Block H(int[] x, long xlen, Block y, long ylen, long outlen) {
        long buflen = (xlen + ylen);
        int[] buf = new int[(int) buflen];

        // Concatenate x and y
        for (int i = 0; i < xlen; i++) {
            buf[i] = x[i];
        }
        for (int i = 0; i < ylen; i++) {
            buf[i + (int) xlen] = y.getData()[i];
        }

        // Create output hash
        byte[] buffer = new byte[buf.length];
        for (int i = 0; i < buffer.length; i++) {
            buffer[i] = (byte) (buf[i] & 0xFF);
        }
        return SHA256.sha256(new Block(buffer.length, buffer));
    }

    public Block encode(Block value, Block key) {
        return hmacSha256(key, value);
    }
}
