package org.ok.protocols;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

class Sha256Context {
    protected Long length;
    protected int[] state = new int[8];
    protected int curlen;
    protected int[] buf = new int[64];
}

class SHA256_HASH {
    int[] bytes = new int[64];
}

class SHA256 {
    private final int BLOCK_SIZE = 64;
    private final int h0 = 0x6a09e667;
    private final int h1 = 0xbb67ae85;
    private final int h2 = 0x3c6ef372;
    private final int h3 = 0xa54ff53a;
    private final int h4 = 0x510e527f;
    private final int h5 = 0x9b05688c;
    private final int h6 = 0x1f83d9ab;
    private final int h7 = 0x5be0cd19;

    private final int[] K = { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
            0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138,
            0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70,
            0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa,
            0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

    private int[] W = new int[64];

    public SHA256() {

    }

    private int ror(int value, int bits) {
        return (((value) >> (bits)) | ((value) << (32 - (bits))));
    }

    private void store32H(int x, int[] y) {
        y[0] = (byte) ((x >> 24) & 255);
        y[1] = (byte) ((x >> 16) & 255);
        y[2] = (byte) ((x >> 8) & 255);
        y[3] = (byte) (x & 255);
    }

    private int load32H(int[] y) {
        return ((y[0] & 0xFF) << 24) | ((y[1] & 0xFF) << 16) | ((y[2] & 0xFF) << 8) | (y[3] & 0xFF);
    }

    private void store64H(long x, int[] y) {
        y[0] = (byte) ((x >> 56) & 0xFF);
        y[1] = (byte) ((x >> 48) & 0xFF);
        y[2] = (byte) ((x >> 40) & 0xFF);
        y[3] = (byte) ((x >> 32) & 0xFF);
        y[4] = (byte) ((x >> 24) & 0xFF);
        y[5] = (byte) ((x >> 16) & 0xFF);
        y[6] = (byte) ((x >> 8) & 0xFF);
        y[7] = (byte) (x & 0xFF);
    }

    private int Ch(int x, int y, int z) {
        return (z ^ (x & (y ^ z)));
    }

    private int Maj(int x, int y, int z) {
        return ((x | y) & z) | (x & y);
    }

    private int S(int x, int n) {
        return ror(x, n);
    }

    private int R(int x, int n) {
        return (x & 0xFFFFFFFF) >> n;
    }

    private int Sigma0(int x) {
        return S(x, 2) ^ S(x, 13) ^ S(x, 22);
    }

    private int Sigma1(int x) {
        return S(x, 6) ^ S(x, 11) ^ S(x, 25);
    }

    private int Gamma0(int x) {
        return S(x, 7) ^ S(x, 18) ^ R(x, 3);
    }

    private int Gamma1(int x) {
        return S(x, 17) ^ S(x, 19) ^ R(x, 10);
    }

    void Sha256Round(int[] sArray, int i) {
        int t0 = sArray[7] + Sigma1(sArray[4]) + Ch(sArray[4], sArray[5], sArray[6]) + K[i] + W[i];
        int t1 = Sigma0(sArray[0]) + Maj(sArray[0], sArray[1], sArray[2]);
        sArray[3] += t0;
        sArray[7] = t0 + t1;
    }

    void TransformFunction(Sha256Context Context, int[] Buffer) {
        int[] s = new int[8];
        int t0;
        int t1;
        int t;
        int i;

        // Copy state into S
        for (i = 0; i < 8; i++) {
            s[i] = Context.state[i];
        }

        // Copy the state into 512-bits into W[0..15]
        for (i = 0; i < 16; i++) {
            W[i] = load32H(Buffer);
        }

        // Fill W[16..63]
        for (i = 16; i < 64; i++) {
            W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];
        }

        // Compress
        for (i = 0; i < 64; i++) {
            Sha256Round(s, i);
            t = s[7];
            s[7] = s[6];
            s[6] = s[5];
            s[5] = s[4];
            s[4] = s[3];
            s[3] = s[2];
            s[2] = s[1];
            s[1] = s[0];
            s[0] = t;
        }

        // Feedback
        for (i = 0; i < 8; i++) {
            Context.state[i] = Context.state[i] + s[i];
        }
    }

    void Sha256Initialise(Sha256Context Context) {
        Context.curlen = 0;
        Context.length = (Long) (long) 0;
        Context.state[0] = 0x6A09E667;
        Context.state[1] = 0xBB67AE85;
        Context.state[2] = 0x3C6EF372;
        Context.state[3] = 0xA54FF53A;
        Context.state[4] = 0x510E527F;
        Context.state[5] = 0x9B05688C;
        Context.state[6] = 0x1F83D9AB;
        Context.state[7] = 0x5BE0CD19;
    }

    public void Sha256Update(Sha256Context context,
            int[] buffer,
            int bufferSize) {
        int n;

        if (context.curlen > context.buf.length) {
            return;
        }

        int offset = 0;
        while (bufferSize > 0) {
            if (context.curlen == 0 && bufferSize >= BLOCK_SIZE) {
                TransformFunction(context, buffer);
                context.length += BLOCK_SIZE * 8;
                offset += BLOCK_SIZE;
                bufferSize -= BLOCK_SIZE;
            } else {
                n = Math.min(bufferSize, (BLOCK_SIZE - context.curlen));
                System.arraycopy(buffer, offset, context.buf, context.curlen, n);
                context.curlen += n;
                offset += n;
                bufferSize -= n;
                if (context.curlen == BLOCK_SIZE) {
                    TransformFunction(context, context.buf);
                    context.length += 8 * BLOCK_SIZE;
                    context.curlen = 0;
                }
            }
        }
    }

    void Sha256Finalise(Sha256Context Context, // [in out]
            SHA256_HASH Digest // [out]
    ) {
        int i;

        if (Context.curlen >= Context.buf.length) {
            return;
        }

        // Increase the length of the message
        Context.length += Context.curlen * 8;

        // Append the '1' bit
        Context.buf[Context.curlen++] = (byte) 0x80;

        // if the length is currently above 56 bytes we append zeros
        // then compress. Then we can fall back to padding zeros and length
        // encoding like normal.
        if (Context.curlen > 56) {
            while (Context.curlen < 64) {
                Context.buf[Context.curlen++] = 0;
            }
            TransformFunction(Context, Context.buf);
            Context.curlen = 0;
        }

        // Pad up to 56 bytes of zeroes
        while (Context.curlen < 56) {
            Context.buf[Context.curlen++] = 0;
        }

        // Store length
        store64H(Context.length, Context.buf);
        TransformFunction(Context, Context.buf);

        // Copy output
        for (i = 0; i < 8; i++) {
            store32H(Context.state[i], Digest.bytes);
        }
    }
}

public class HMAC256 {
    public HMAC256() {

    }

    public void testPrint() {
        String str_data = "Hello World!";
        String str_key = "super-secret-key";
        int[] out = new int[64];
        char[] out_str = new char[64 * 2 + 1];
        int i;

        // Call hmac-sha256 function
        int[] tempKey = new int[str_key.getBytes().length];
        for (int ii = 0; ii < str_key.getBytes().length; ii++) {
            tempKey[ii] = str_key.getBytes()[ii];
        }
        int[] tempData = new int[str_data.getBytes().length];
        for (int ii = 0; ii < str_data.getBytes().length; ii++) {
            tempData[ii] = str_data.getBytes()[ii];
        }
        hmacSha256(tempKey, str_key.getBytes().length, tempData, str_data.getBytes().length, out,
                out.length);
        for (int b : out) {
            System.out.println(b);
        }
    }

    private static final int SHA256_BLOCK_SIZE = 64;
    private static final int SHA256_HASH_SIZE = 32;

    public static int hmacSha256(int[] key, int keylen, int[] data, int datalen, int[] out, int outlen) {
        int[] k = new int[SHA256_BLOCK_SIZE];
        int[] k_ipad = new int[SHA256_BLOCK_SIZE];
        int[] k_opad = new int[SHA256_BLOCK_SIZE];
        int[] ihash = new int[SHA256_HASH_SIZE];
        int[] ohash = new int[SHA256_HASH_SIZE];

        Arrays.fill(k_ipad, (byte) 0x36);
        Arrays.fill(k_opad, (byte) 0x5c);

        if (keylen > SHA256_BLOCK_SIZE) {
            // If the key is larger than the hash algorithm's block size, we must digest it
            // first.
            sha256(key, keylen, k, k.length);
        } else {
            System.arraycopy(key, 0, k, 0, keylen);
        }

        for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
            k_ipad[i] ^= k[i];
            k_opad[i] ^= k[i];
        }

        // Perform HMAC algorithm: H(K XOR opad, H(K XOR ipad, data))
        H(k_ipad, k_ipad.length, data, datalen, ihash, ihash.length);
        H(k_opad, k_opad.length, ihash, ihash.length, ohash, ohash.length);

        int sz = Math.min(outlen, SHA256_HASH_SIZE);
        System.arraycopy(ohash, 0, out, 0, sz);
        return sz;
    }

    private static int[] H(int[] x, int xlen, int[] y, int ylen, int[] out, int outlen) {
        int[] buf = new int[xlen + ylen];
        System.arraycopy(x, 0, buf, 0, xlen);
        System.arraycopy(y, 0, buf, xlen, ylen);
        return sha256(buf, buf.length, out, outlen);
    }

    private static int[] sha256(int[] data, int datalen, int[] out, int outlen) {
        // Assuming Sha256Context and SHA256_HASH are defined elsewhere
        Sha256Context ctx = new Sha256Context();
        SHA256_HASH hash = new SHA256_HASH();
        SHA256 sha256 = new SHA256();
        sha256.Sha256Initialise(ctx);
        sha256.Sha256Update(ctx, data, datalen);
        sha256.Sha256Finalise(ctx, hash);

        int sz = Math.min(outlen, SHA256_HASH_SIZE);
        System.arraycopy(hash.bytes, 0, out, 0, sz);
        return out;
    }

}
