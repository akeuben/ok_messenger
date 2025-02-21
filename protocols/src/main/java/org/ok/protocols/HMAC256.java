package org.ok.protocols;

import java.util.Arrays;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

class Sha256Context {
    long length; // Always signed
    int[] state = new int[8]; // use `& 0x00000000ffffffffL` to print
    int curlen;
    byte[] buf = new byte[64];

    public Sha256Context() {

    }
}

class SHA256_HASH {
    byte[] bytes;

    public SHA256_HASH(long size) {
        bytes = new byte[(int) size];
    }
}

class HmacSha256 {
    static final int SHA256_HASH_SIZE = 256 / 8;
    static final int BLOCK_SIZE = 64;
    static final int SHA256_BLOCK_SIZE = 64;

    static int[] K = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

    // public static void main(String args[]) {
    // String str_data = "hello";
    // String str_key = "keykey";
    // byte[] out = new byte[(int) SHA256_HASH_SIZE];
    // // char out_str[SHA256_HASH_SIZE * 2 + 1];
    // int i;

    // // Call hmac-sha256 function
    // try {
    // for (byte b : str_data.getBytes("US-ASCII")) {
    // System.out.printf("%02x\n", b & 0xff);
    // }
    // } catch (UnsupportedEncodingException e) {
    // // TODO Auto-generated catch block
    // e.printStackTrace();
    // }
    // try {
    // out = hmac_sha256(str_key.getBytes("US-ASCII"), str_key.length(),
    // str_data.getBytes("US-ASCII"),
    // str_data.length(), out,
    // out.length);
    // } catch (UnsupportedEncodingException e) {
    // // TODO Auto-generated catch block
    // e.printStackTrace();
    // }

    // for (byte b : out) {
    // System.out.printf("%02x", b);
    // }
    // System.out.println("\n209800404ad6227356941d9b1fd44a610d178902db5e9ca2a25d8cf1f8ecaf12
    // ---");
    // }

    static int ror(int value, int bits) {
        return ((value) >> (bits)) | ((value) << (32 - (bits)));
    }

    static int MIN(int x, int y) {
        return (x < y) ? x : y;
    }

    static void STORE32H(int x, byte[] y) {
        y[0] = (byte) ((x >> 24) & 255);
        y[1] = (byte) ((x >> 16) & 255);
        y[2] = (byte) ((x >> 8) & 255);
        y[3] = (byte) (x & 255);
    }

    static int LOAD32H(byte[] y, int offset) {
        return ((int) (y[offset] & 255) << 24) | ((int) (y[offset + 1] & 255) << 16)
                | ((int) (y[offset + 2] & 255) << 8)
                | ((int) (y[offset + 3] & 255));
    }

    static void STORE64H(long x, byte[] y) {
        y[0] = (byte) ((x >> 56) & 255);
        y[1] = (byte) ((x >> 48) & 255);
        y[2] = (byte) ((x >> 40) & 255);
        y[3] = (byte) ((x >> 32) & 255);
        y[4] = (byte) ((x >> 24) & 255);
        y[5] = (byte) ((x >> 16) & 255);
        y[6] = (byte) ((x >> 8) & 255);
        y[7] = (byte) (x & 255);
    }

    static int Ch(int x, int y, int z) {
        return z ^ (x & (y ^ z));
    }

    static int Maj(int x, int y, int z) {
        return ((x | y) & z) | (x & y);
    }

    static int SS(int x, int n) {
        return ror((x), (n));
    }

    static int R(int x, int n) {
        return ((x) & 0xFFFFFFFF) >> (n);
    }

    static int Sigma0(int x) {
        return SS(x, 2) ^ SS(x, 13) ^ SS(x, 22);
    }

    static int Sigma1(int x) {
        return SS(x, 6) ^ SS(x, 11) ^ SS(x, 25);
    }

    static int Gamma0(int x) {
        return SS(x, 7) ^ SS(x, 18) ^ R(x, 3);
    }

    static int Gamma1(int x) {
        return SS(x, 17) ^ SS(x, 19) ^ R(x, 10);
    }

    static void Sha256Round(int[] S, int i, int[] W) {
        int t0 = S[7] + Sigma1(S[4]) + Ch(S[4], S[5], S[6]) + K[i] + W[i];
        int t1 = Sigma0(S[0]) + Maj(S[0], S[1], S[2]);
        S[3] += t0;
        S[7] = t0 + t1;
    }

    static void TransformFunction(Sha256Context Context, byte[] Buffer) {
        int[] S = new int[8];
        int[] W = new int[64];
        int t;
        int i;

        // Copy state into S
        for (i = 0; i < 8; i++) {
            S[i] = Context.state[i];
        }

        // Copy the state into 512-bits into W[0..15]
        for (i = 0; i < 16; i++) {
            // W[i] = LOAD32H(Buffer);// TODO fix it
            W[i] = LOAD32H(Buffer, 4 * i);
        }
        for (i = 0; i < 16; i++) {// Second call missing 228
            System.out.printf("W Tr %02x\n", W[i]);
        }

        // Fill W[16..63]
        for (i = 16; i < 64; i++) {
            W[i] = Gamma1(W[(int) (i - 2)]) + W[(int) (i - 7)] + Gamma0(W[(int) (i - 15)]) + W[(int) (i - 16)];
        }

        // Compress
        for (i = 0; i < 64; i++) {
            Sha256Round(S, i, W);
            t = S[7];
            S[7] = S[6];
            S[6] = S[5];
            S[5] = S[4];
            S[4] = S[3];
            S[3] = S[2];
            S[2] = S[1];
            S[1] = S[0];
            S[0] = t;
        }

        // Feedback
        for (i = 0; i < 8; i++) {
            Context.state[i] = Context.state[i] + S[i];
        }
    }

    static void Sha256Initialise(Sha256Context Context) {
        Context.curlen = 0;
        Context.length = 0;
        Context.state[0] = 0x6A09E667;
        Context.state[1] = 0xBB67AE85;
        Context.state[2] = 0x3C6EF372;
        Context.state[3] = 0xA54FF53A;
        Context.state[4] = 0x510E527F;
        Context.state[5] = 0x9B05688C;
        Context.state[6] = 0x1F83D9AB;
        Context.state[7] = 0x5BE0CD19;

    }

    static byte[] deepCopy(byte[] barray) {
        byte[] newArray = new byte[barray.length];
        for (int i = 0; i < newArray.length; i++) {
            newArray[i] = barray[i];
        }
        return newArray;
    }

    static void Sha256Update(Sha256Context Context, byte[] Buffer, long BufferSize) {
        int n;
        while (BufferSize > 0) {
            if (Context.curlen == 0 && BufferSize >= BLOCK_SIZE) {
                TransformFunction(Context, Buffer);
                Context.length += BLOCK_SIZE * 8;
                Buffer = shiftBuffer(Buffer, BLOCK_SIZE);
                BufferSize -= BLOCK_SIZE;
            } else {
                n = MIN((int) BufferSize, BLOCK_SIZE - Context.curlen);
                System.arraycopy(Buffer, 0, Context.buf, Context.curlen, n);
                Context.curlen += n;
                Buffer = shiftBuffer(Buffer, n);
                BufferSize -= n;
                if (Context.curlen == BLOCK_SIZE) {
                    TransformFunction(Context, Context.buf);
                    Context.length += 8 * BLOCK_SIZE;
                    Context.curlen = 0;
                }
            }
        }
    }

    private static byte[] shiftBuffer(byte[] buffer, int shiftBy) {
        byte[] newBuffer = new byte[buffer.length - shiftBy];
        System.arraycopy(buffer, shiftBy, newBuffer, 0, newBuffer.length);
        return newBuffer;
    }

    static void Sha256Finalise(Sha256Context Context, SHA256_HASH Digest) {
        int i;

        if (Context.curlen >= Context.buf.length) {
            return;
        }

        // Increase the length of the message
        Context.length += Context.curlen * 8;

        // Append the '1' bit
        Context.buf[(int) Context.curlen++] = (byte) 0x80;

        // if the length is currently above 56 bytes we append zeros
        // then compress. Then we can fall back to padding zeros and length
        // encoding like normal.
        if (Context.curlen > 56) {
            while (Context.curlen < 64) {
                Context.buf[(int) Context.curlen++] = (byte) 0;
            }
            TransformFunction(Context, Context.buf);
            Context.curlen = 0;
        }

        // Pad up to 56 bytes of zeroes
        while (Context.curlen < 56) {
            Context.buf[(int) Context.curlen++] = (byte) 0;
        }

        // Store length
        // STORE64H(Context.length, Context.buf + 56);
        // System.out.println(Context.length);
        // STORE64H(Context.length, java.util.Arrays.copyOfRange(Digest.bytes, 56, 56 +
        // 4));
        STORE64H(Context.length, Digest.bytes);
        TransformFunction(Context, Context.buf);

        // Copy output
        for (i = 0; i < 8; i++) {
            STORE32H(Context.state[i],
                    java.util.Arrays.copyOfRange(Digest.bytes, (int) (4 * i), (int) (4 * i + 4)));
        }
    }

    static byte[] hmac_sha256(byte[] key, long keylen, byte[] data, long datalen, byte[] out, long outlen) {
        byte[] k = new byte[(int) SHA256_BLOCK_SIZE];
        byte[] k_ipad = new byte[(int) SHA256_BLOCK_SIZE];
        byte[] k_opad = new byte[(int) SHA256_BLOCK_SIZE];
        byte[] ihash = new byte[(int) SHA256_HASH_SIZE];
        byte[] ohash = new byte[(int) SHA256_HASH_SIZE];
        long sz;
        int i;
        for (i = 0; i < k.length; i++) {
            k[i] = 0;
        }
        for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
            k_ipad[i] = 0x36;
        }
        for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
            k_opad[i] = 0x5c;
        }

        if (keylen > SHA256_BLOCK_SIZE) {
            // If the key is larger than the hash algorithm's
            // block size, we must digest it first.
            sha256(key, k.length);
        } else {
            for (i = 0; i < keylen; i++) {
                k[i] = (byte) key[i];
            }
            // memcpy(k, key, keylen);
            // k = Arrays.copyOf(key, (int) keylen-1);
        }

        for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
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
        // memcpy(out, ohash, sz);
        return out;
    }

    static byte[] H(byte[] x, long xlen, byte[] y, long ylen, byte[] out, long outlen) {
        byte[] result;
        long buflen = (xlen + ylen);
        byte[] buf = new byte[(int) buflen];

        for (int i = 0; i < xlen; i++) {
            buf[i] = x[i];
        }
        for (int i = 0; i < ylen; i++) {
            buf[i + (int) xlen] = y[i];
        }
        // result = sha256(buf, buflen, out, outlen);
        result = sha256(buf, outlen);
        return result;
    }

    public static byte[] sha256(byte[] data, long outlen) {
        if (data == null || outlen <= 0) {
            return null; // Handle invalid input
        }

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);

            // Trim or pad the output to the requested length
            return Arrays.copyOf(hash, Math.min((int) outlen, hash.length));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not found", e);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // static byte[] sha256(byte[] data, long datalen, byte[] out, long outlen) {
    // long sz;
    // Sha256Context ctx = new Sha256Context();
    // SHA256_HASH hash = new SHA256_HASH(SHA256_HASH_SIZE);

    // Sha256Initialise(ctx);
    // Sha256Update(ctx, data, datalen);
    // for (int i = 0; i < data.length; i++) {
    // System.out.printf("data %02x\n", data[i]);
    // }
    // Sha256Finalise(ctx, hash);

    // sz = (outlen > SHA256_HASH_SIZE) ? SHA256_HASH_SIZE : outlen;
    // for (int i = 0; i < sz; i++) {
    // out[i] = hash.bytes[i];
    // }
    // return out;
    // // return memcpy(out, hash.bytes, sz);
    // }
}

public class HMAC256 {
    public HMAC256() {

    }

    public Block encode(Block value, Block key) {
        System.out.println();
        System.out.println();
        byte[] out = new byte[32];
        byte[] tempKey = new byte[key.getSizeBytes()];
        for (int i = 0; i < key.getSizeBytes(); i++) {
            tempKey[i] = (byte) key.getData()[i];
        }
        byte[] tempData = new byte[value.getSizeBytes()];
        for (int i = 0; i < value.getSizeBytes(); i++) {
            tempData[i] = (byte) value.getData()[i];
        }
        HmacSha256.hmac_sha256(tempKey, key.getSizeBytes(), tempData, value.getSizeBytes(), out,
                out.length);
        char[] charOut = new char[32];
        for (int i = 0; i < out.length; i++) {
            charOut[i] = (char) out[i];
        }
        return new Block(32, charOut);
    }

    public boolean verify(Block hmac, Block key) {//Probably not ready yet
        return Arrays.equals(hmac.getData(), key.getData());
    }

    public void testPrint() {
        String str_data = "hello";
        String str_key = "keykey";
        byte[] out = new byte[32];

        // Call hmac-sha256 function
        byte[] tempKey = new byte[str_key.getBytes().length];
        for (int ii = 0; ii < str_key.getBytes().length; ii++) {
            tempKey[ii] = str_key.getBytes()[ii];
        }
        byte[] tempData = new byte[str_data.getBytes().length];
        for (int ii = 0; ii < str_data.getBytes().length; ii++) {
            tempData[ii] = str_data.getBytes()[ii];
        }
        HmacSha256.hmac_sha256(tempKey, str_key.getBytes().length, tempData, str_data.getBytes().length, out,
                out.length);
        for (byte b : out) {
            System.out.printf("%02x", b);
        }
        System.out.println();
    }

}
