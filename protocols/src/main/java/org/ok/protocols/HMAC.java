package org.ok.protocols;

public class HMAC {

    protected final int SHA256_HASH_SIZE = 32;
    protected final int BLOCK_SIZE = 64;

    protected SHA256 sha;

    public HMAC() {
        sha = new SHA256();
    }

    protected int[] hmac_sha256(int[] key, long keylen, int[] data, long datalen, int[] out, long outlen) {
        int[] k = new int[(int) BLOCK_SIZE];
        int[] k_ipad = new int[(int) BLOCK_SIZE];
        int[] k_opad = new int[(int) BLOCK_SIZE];
        int[] ihash = new int[(int) SHA256_HASH_SIZE];
        int[] ohash = new int[(int) SHA256_HASH_SIZE];
        long sz;
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
            sha.sha256(key, out);
        } else {
            for (i = 0; i < keylen; i++) {
                k[i] = (byte) key[i];
            }
        }

        for (i = 0; i < BLOCK_SIZE; i++) {
            k_ipad[i] ^= k[i];
            k_opad[i] ^= k[i];
        }

        // Perform HMAC algorithm: ( https://tools.ietf.org/html/rfc2104 )
        // `H(K XOR opad, H(K XOR ipad, data))`
        ihash = H(k_ipad, k_ipad.length, data, datalen, ihash, ihash.length);
        ohash = H(k_opad, k_opad.length, ihash, ihash.length, ohash, ohash.length);

        sz = (outlen > SHA256_HASH_SIZE) ? SHA256_HASH_SIZE : outlen;
        for (i = 0; i < sz; i++) {
            out[i] = ohash[i];
        }
        return out;
    }

    protected int[] H(int[] x, long xlen, int[] y, long ylen, int[] out, long outlen) {
        int[] result;
        long buflen = (xlen + ylen);
        int[] buf = new int[(int) buflen];

        for (int i = 0; i < xlen; i++) {
            buf[i] = x[i];
        }
        for (int i = 0; i < ylen; i++) {
            buf[i + (int) xlen] = y[i];
        }
        result = sha.sha256(buf, out);
        return result;
    }

    public Block encode(Block value, Block key) {
        int[] out = new int[SHA256_HASH_SIZE];
        int[] tempKey = new int[key.getSizeBytes()];
        for (int i = 0; i < key.getSizeBytes(); i++) {
            tempKey[i] = key.getData()[i] & 0xFF;
        }
        int[] tempData = new int[value.getSizeBytes()];
        for (int i = 0; i < value.getSizeBytes(); i++) {
            tempData[i] = value.getData()[i] & 0xFF;
        }
        hmac_sha256(tempKey, key.getSizeBytes(), tempData, value.getSizeBytes(), out,
                out.length);
        char[] charOut = new char[SHA256_HASH_SIZE];
        for (int i = 0; i < out.length; i++) {
            charOut[i] = (char) out[i];
        }

        return new Block(SHA256_HASH_SIZE, charOut);
    }
}
