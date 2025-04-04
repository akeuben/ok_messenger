/*
 * Joshua Liu
 * SHA256 implementation
 * Using long to represent an unsigned int
 * Using int to represent an unsigned byte
 */

package org.ok.protocols.hmacsha256;

import org.ok.protocols.Block;

public class SHA256 {

    private static class Sha256Context {
        long length;
        long[] state = new long[8];
        int curlen;
        int[] buf = new int[64];

        public Sha256Context() {

        }
    }

    private static class SHA256_HASH {
        int[] bytes;

        public SHA256_HASH(int size) {
            bytes = new int[size];
        }
    }

    private static final int SHA256_HASH_SIZE = 256 / 8;
    private static final int BLOCK_SIZE = 64;

    // Predefined constants for sha256
    private static long[] K = {
            0x428a2f98L, 0x71374491L, 0xb5c0fbcfL, 0xe9b5dba5L, 0x3956c25bL, 0x59f111f1L, 0x923f82a4L, 0xab1c5ed5L,
            0xd807aa98L, 0x12835b01L, 0x243185beL, 0x550c7dc3L, 0x72be5d74L, 0x80deb1feL, 0x9bdc06a7L, 0xc19bf174L,
            0xe49b69c1L, 0xefbe4786L, 0x0fc19dc6L, 0x240ca1ccL, 0x2de92c6fL, 0x4a7484aaL, 0x5cb0a9dcL, 0x76f988daL,
            0x983e5152L, 0xa831c66dL, 0xb00327c8L, 0xbf597fc7L, 0xc6e00bf3L, 0xd5a79147L, 0x06ca6351L, 0x14292967L,
            0x27b70a85L, 0x2e1b2138L, 0x4d2c6dfcL, 0x53380d13L, 0x650a7354L, 0x766a0abbL, 0x81c2c92eL, 0x92722c85L,
            0xa2bfe8a1L, 0xa81a664bL, 0xc24b8b70L, 0xc76c51a3L, 0xd192e819L, 0xd6990624L, 0xf40e3585L, 0x106aa070L,
            0x19a4c116L, 0x1e376c08L, 0x2748774cL, 0x34b0bcb5L, 0x391c0cb3L, 0x4ed8aa4aL, 0x5b9cca4fL, 0x682e6ff3L,
            0x748f82eeL, 0x78a5636fL, 0x84c87814L, 0x8cc70208L, 0x90befffaL, 0xa4506cebL, 0xbef9a3f7L, 0xc67178f2L };

    private static int[] store32h(long x, int[] y, int offset) {
        y[0 + offset] = (int) (((x & 0xFFFFFFFFL) >> 24) & 0xFF);
        y[1 + offset] = (int) (((x & 0xFFFFFFFFL) >> 16) & 0xFF);
        y[2 + offset] = (int) (((x & 0xFFFFFFFFL) >> 8) & 0xFF);
        y[3 + offset] = (int) ((x & 0xFFFFFFFFL) & 0xFF);
        return y;
    }

    // Right rotate
    private static long ror(long value, long bits) {
        return ((((value & 0xFFFFFFFFL) >> (bits & 0xFFFFFFFFL)) & 0xFFFFFFFFL)
                | (((value & 0xFFFFFFFFL) << ((32 - (bits & 0xFFFFFFFFL)) & 0xFFFFFFFFL)) & 0xFFFFFFFFL)) & 0xFFFFFFFFL;
    }

    private static long MIN(long x, long y) {
        return (x < y) ? x & 0xFFFFFFFFL : y & 0xFFFFFFFFL;
    }

    private static long load32h(int[] y, int offset) {
        return ((long) ((y)[0 + offset] & 255) << 24) | ((long) ((y)[1 + offset] & 255) << 16) |
                ((long) ((y)[2 + offset] & 255) << 8) | ((long) ((y)[3 + offset] & 255));

    }

    private static void store64h(long x, int[] y) {
        y[0 + 56] = (byte) (((x & 0xFFFFFFFFL) >> 56) & 0xFF);
        y[1 + 56] = (byte) (((x & 0xFFFFFFFFL) >> 48) & 0xFF);
        y[2 + 56] = (byte) (((x & 0xFFFFFFFFL) >> 40) & 0xFF);
        y[3 + 56] = (byte) (((x & 0xFFFFFFFFL) >> 32) & 0xFF);
        y[4 + 56] = (byte) (((x & 0xFFFFFFFFL) >> 24) & 0xFF);
        y[5 + 56] = (byte) (((x & 0xFFFFFFFFL) >> 16) & 0xFF);
        y[6 + 56] = (byte) (((x & 0xFFFFFFFFL) >> 8) & 0xFF);
        y[7 + 56] = (byte) ((x & 0xFFFFFFFFL) & 0xFF);

    }

    private static long choose(long x, long y, long z) {
        return ((z & 0xFFFFFFFFL)
                ^ (((x & 0xFFFFFFFFL) & (((y & 0xFFFFFFFFL) ^ (z & 0xFFFFFFFFL)) & 0xFFFFFFFFL)) & 0xFFFFFFFFL))
                & 0xFFFFFFFFL;
    }

    private static long majority(long x, long y, long z) {
        return ((((((x & 0xFFFFFFFFL) | (y & 0xFFFFFFFFL)) & 0xFFFFFFFFL) & (z & 0xFFFFFFFFL)) & 0xFFFFFFFFL)
                | (((x & 0xFFFFFFFFL) & (y & 0xFFFFFFFFL)) & 0xFFFFFFFFL)) & 0xFFFFFFFFL;
    }

    private static long s(long x, long n) {
        return ror((x & 0xFFFFFFFFL), (n & 0xFFFFFFFFL)) & 0xFFFFFFFFL;
    }

    private static long r(long x, long n) {
        return (((x & 0xFFFFFFFFL) & 0xFFFFFFFFL) >> (n & 0xFFFFFFFFL)) & 0xFFFFFFFFL;
    }

    private static long sigma0(long x) {
        return (((s(x & 0xFFFFFFFFL, 2) & 0xFFFFFFFFL)
                ^ (s(x & 0xFFFFFFFFL, 13) & 0xFFFFFFFFL) & 0xFFFFFFFFL)
                ^ (s(x & 0xFFFFFFFFL, 22) & 0xFFFFFFFFL)) & 0xFFFFFFFFL;
    }

    private static long sigma1(long x) {
        return ((((s(x & 0xFFFFFFFFL, 6) & 0xFFFFFFFFL) ^ (s(x & 0xFFFFFFFFL, 11) & 0xFFFFFFFFL)) & 0xFFFFFFFFL)
                ^ (s(x & 0xFFFFFFFFL, 25) & 0xFFFFFFFFL)) & 0xFFFFFFFFL;
    }

    private static long gamma0(long x) {
        return ((((s(x & 0xFFFFFFFFL, 7) & 0xFFFFFFFFL) ^ (s(x & 0xFFFFFFFFL, 18) & 0xFFFFFFFFL)) & 0xFFFFFFFFL)
                ^ (r(x & 0xFFFFFFFFL, 3) & 0xFFFFFFFFL)) & 0xFFFFFFFFL;
    }

    private static long gamma1(long x) {
        return ((((s(x & 0xFFFFFFFFL, 17) & 0xFFFFFFFFL)
                ^ (s(x & 0xFFFFFFFFL, 19) & 0xFFFFFFFFL)) & 0xFFFFFFFFL)
                ^ (r(x & 0xFFFFFFFFL, 10) & 0xFFFFFFFFL)) & 0xFFFFFFFFL;
    }

    private static long[] sha256round(long[] S, int i, long[] W) {
        long t0 = ((((((((((S[7] & 0xFFFFFFFFL) + (sigma1(S[4] & 0xFFFFFFFFL) & 0xFFFFFFFFL)) & 0xFFFFFFFFL)
                + (choose(S[4] & 0xFFFFFFFFL, S[5] & 0xFFFFFFFFL, S[6] & 0xFFFFFFFFL) & 0xFFFFFFFFL)) & 0xFFFFFFFFL)
                + (K[i] & 0xFFFFFFFFL)) & 0xFFFFFFFFL) + (W[i] & 0xFFFFFFFFL)) & 0xFFFFFFFFL)) & 0xFFFFFFFFL;
        long t1 = ((sigma0(S[0] & 0xFFFFFFFFL) & 0xFFFFFFFFL)
                + (majority(S[0] & 0xFFFFFFFFL, S[1] & 0xFFFFFFFFL, S[2] & 0xFFFFFFFFL) & 0xFFFFFFFFL))
                & 0xFFFFFFFFL;
        S[3] += t0 & 0xFFFFFFFFL;
        S[7] = ((t0 & 0xFFFFFFFFL) + (t1 & 0xFFFFFFFFL)) & 0xFFFFFFFFL;
        return S;
    }

    private static void transformFunction(Sha256Context context, int[] buffer) {
        long[] S = new long[8];
        long[] W = new long[64];
        long t;
        int i;

        // Copy state into S
        for (i = 0; i < 8; i++) {
            S[i] = context.state[i] & 0xFFFFFFFFL;
        }

        // Copy the state into 512-bits into W[0..15]
        for (i = 0; i < 16; i++) {
            W[i] = load32h(buffer, 4 * i) & 0xFFFFFFFFL;
        }

        // Fill W[16..63]
        for (i = 16; i < 64; i++) {
            W[i] = (((((gamma1(W[i - 2] & 0xFFFFFFFFL) + (W[i - 7] & 0xFFFFFFFFL)) & 0xFFFFFFFFL)
                    + gamma0(W[i - 15] & 0xFFFFFFFFL)) & 0xFFFFFFFFL)
                    + (W[i - 16] & 0xFFFFFFFFL))
                    & 0xFFFFFFFFL;
        }

        // Compress
        for (i = 0; i < 64; i++) {
            S = sha256round(S, i, W);
            t = S[7] & 0xFFFFFFFFL;
            S[7] = S[6] & 0xFFFFFFFFL;
            S[6] = S[5] & 0xFFFFFFFFL;
            S[5] = S[4] & 0xFFFFFFFFL;
            S[4] = S[3] & 0xFFFFFFFFL;
            S[3] = S[2] & 0xFFFFFFFFL;
            S[2] = S[1] & 0xFFFFFFFFL;
            S[1] = S[0] & 0xFFFFFFFFL;
            S[0] = t & 0xFFFFFFFFL;
        }

        // Feedback
        for (i = 0; i < 8; i++) {
            context.state[i] = ((context.state[i] & 0xFFFFFFFFL) + (S[i] & 0xFFFFFFFFL)) & 0XFFFFFFFFL;
        }
    }

    private static void sha256initialize(Sha256Context context) {
        context.curlen = 0;
        context.length = 0;
        context.state[0] = 0x6A09E667L;
        context.state[1] = 0xBB67AE85L;
        context.state[2] = 0x3C6EF372L;
        context.state[3] = 0xA54FF53AL;
        context.state[4] = 0x510E527FL;
        context.state[5] = 0x9B05688CL;
        context.state[6] = 0x1F83D9ABL;
        context.state[7] = 0x5BE0CD19L;
    }

    private static void sha256update(Sha256Context context, byte[] buf, long bufferSize) {
        long n;
        int[] buffer = new int[buf.length];
        for (int i = 0; i < buf.length; i++) {
            buffer[i] = buf[i];
        }
        while (bufferSize > 0) {
            if (context.curlen == 0 && bufferSize >= BLOCK_SIZE) {

                transformFunction(context, buffer);
                context.length += BLOCK_SIZE * 8;
                buffer = shiftBuffer(buffer, BLOCK_SIZE);

                bufferSize -= BLOCK_SIZE;
            } else {
                n = MIN((int) bufferSize, BLOCK_SIZE - context.curlen) & 0xFFFFFFFFL;
                System.arraycopy(buffer, 0, context.buf, context.curlen, (int) (n & 0xFFFFFFFFL));
                context.curlen += n;
                buffer = shiftBuffer(buffer, (int) (n & 0xFFFFFFFFL));

                bufferSize -= n;
                if (context.curlen == BLOCK_SIZE) {
                    transformFunction(context, context.buf);
                    context.length += 8 * BLOCK_SIZE;
                    context.curlen = 0;
                }
            }
        }
    }

    private static int[] shiftBuffer(int[] buffer, int shiftBy) {
        int[] newBuffer = new int[buffer.length - shiftBy];
        System.arraycopy(buffer, shiftBy, newBuffer, 0, newBuffer.length);
        for (int i = 0; i < newBuffer.length; i++) {
            newBuffer[i] &= 0xFF;
        }
        return newBuffer;
    }

    private static void sha256finalise(Sha256Context context, SHA256_HASH digest) {
        if (context.curlen >= context.buf.length) {
            return;
        }

        // Increase the length of the message
        context.length += context.curlen * 8;

        // Append the '1' bit
        context.buf[(int) context.curlen++] = (0x80 & 0xFF);

        // if the length is currently above 56 bytes we append zeros
        // then compress. Then we can fall back to padding zeros and length
        // encoding like normal.
        if (context.curlen > 56) {
            while (context.curlen < 64) {
                context.buf[(int) context.curlen++] = 0;
            }
            transformFunction(context, context.buf);
            context.curlen = 0;
        }

        // Pad up to 56 bytes of zeroes
        while (context.curlen < 56) {
            context.buf[(int) context.curlen++] = (byte) 0 & 0xFF;
        }

        // Store length
        store64h(context.length, context.buf);
        transformFunction(context, context.buf);

        // Copy output
        for (int i = 0; i < 8; i++) {
            int[] y = store32h(context.state[i] & 0xFFFFFFFFL, digest.bytes, 4 * i);
            digest.bytes[4 * i] = y[4 * i];
            digest.bytes[1 + 4 * i] = y[1 + 4 * i];
            digest.bytes[2 + 4 * i] = y[2 + 4 * i];
            digest.bytes[3 + 4 * i] = y[3 + 4 * i];
        }
    }

    public static Block sha256(Block data) {
        Sha256Context ctx = new Sha256Context();
        SHA256_HASH hash = new SHA256_HASH(SHA256_HASH_SIZE);

        sha256initialize(ctx);
        sha256update(ctx, data.getData(), data.getData().length);
        sha256finalise(ctx, hash);

        // Generate output hash
        byte[] bytes = new byte[32];
        for (int i = 0; i < 32; i++) {
            bytes[i] = (byte) (hash.bytes[i] & 0xFF);
        }

        return new Block(bytes.length, bytes);
    }
}
