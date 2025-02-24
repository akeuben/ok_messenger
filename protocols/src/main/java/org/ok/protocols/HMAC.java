package org.ok.protocols;

public class HMAC {

    protected final int SHA256_HASH_SIZE = 32;
    protected final int BLOCK_SIZE = 64;

    protected SHA256 sha;

    public HMAC() {
        sha = new SHA256();
    }

    protected byte[] hmac_sha256(byte[] key, long keylen, byte[] data, long datalen, byte[] out, long outlen) {
        byte[] k = new byte[(int) BLOCK_SIZE];
        byte[] k_ipad = new byte[(int) BLOCK_SIZE];
        byte[] k_opad = new byte[(int) BLOCK_SIZE];
        byte[] ihash = new byte[(int) SHA256_HASH_SIZE];
        byte[] ohash = new byte[(int) SHA256_HASH_SIZE];
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
            sha.sha256(key, k.length);
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

    protected byte[] H(byte[] x, long xlen, byte[] y, long ylen, byte[] out, long outlen) {
        byte[] result;
        long buflen = (xlen + ylen);
        byte[] buf = new byte[(int) buflen];

        for (int i = 0; i < xlen; i++) {
            buf[i] = x[i];
        }
        for (int i = 0; i < ylen; i++) {
            buf[i + (int) xlen] = y[i];
        }
        result = sha.sha256(buf, outlen);
        return result;
    }

    public Block encode(Block value, Block key) {
        System.out.println();
        System.out.println();
        byte[] out = new byte[SHA256_HASH_SIZE];
        byte[] tempKey = new byte[key.getSizeBytes()];
        for (int i = 0; i < key.getSizeBytes(); i++) {
            tempKey[i] = (byte) key.getData()[i];
        }
        byte[] tempData = new byte[value.getSizeBytes()];
        for (int i = 0; i < value.getSizeBytes(); i++) {
            tempData[i] = (byte) value.getData()[i];
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
