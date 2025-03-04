
import java.nio.charset.StandardCharsets;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class Sha256Context {
    long length; // Always signed
    long[] state = new long[8]; // int
    int curlen;
    int[] buf = new int[64];

    public Sha256Context() {

    }
}

class SHA256_HASH {
    int[] bytes;

    public SHA256_HASH(int size) {
        bytes = new int[size];
    }
}

public class SHA256 {

    static final int SHA256_HASH_SIZE = 256 / 8;
    static final int BLOCK_SIZE = 64;
    static final int SHA256_BLOCK_SIZE = 64;

    static long[] K = {
            0x428a2f98L, 0x71374491L, 0xb5c0fbcfL, 0xe9b5dba5L, 0x3956c25bL, 0x59f111f1L, 0x923f82a4L, 0xab1c5ed5L,
            0xd807aa98L, 0x12835b01L, 0x243185beL, 0x550c7dc3L, 0x72be5d74L, 0x80deb1feL, 0x9bdc06a7L, 0xc19bf174L,
            0xe49b69c1L, 0xefbe4786L, 0x0fc19dc6L, 0x240ca1ccL, 0x2de92c6fL, 0x4a7484aaL, 0x5cb0a9dcL, 0x76f988daL,
            0x983e5152L, 0xa831c66dL, 0xb00327c8L, 0xbf597fc7L, 0xc6e00bf3L, 0xd5a79147L, 0x06ca6351L, 0x14292967L,
            0x27b70a85L, 0x2e1b2138L, 0x4d2c6dfcL, 0x53380d13L, 0x650a7354L, 0x766a0abbL, 0x81c2c92eL, 0x92722c85L,
            0xa2bfe8a1L, 0xa81a664bL, 0xc24b8b70L, 0xc76c51a3L, 0xd192e819L, 0xd6990624L, 0xf40e3585L, 0x106aa070L,
            0x19a4c116L, 0x1e376c08L, 0x2748774cL, 0x34b0bcb5L, 0x391c0cb3L, 0x4ed8aa4aL, 0x5b9cca4fL, 0x682e6ff3L,
            0x748f82eeL, 0x78a5636fL, 0x84c87814L, 0x8cc70208L, 0x90befffaL, 0xa4506cebL, 0xbef9a3f7L, 0xc67178f2L };

    static int[] STORE32H(long x, int[] y, int offset) {

        // System.out.printf("Y: %02x %02x %02x %02x\n", y[0], y[1], y[2], y[3]);
        y[0 + offset] = (int) (((x & 0xFFFFFFFFL) >> 24) & 0xFF);
        y[1 + offset] = (int) (((x & 0xFFFFFFFFL) >> 16) & 0xFF);
        y[2 + offset] = (int) (((x & 0xFFFFFFFFL) >> 8) & 0xFF);
        y[3 + offset] = (int) ((x & 0xFFFFFFFFL) & 0xFF);
        // System.out.printf("YY: %02x %02x %02x %02x\n", y[0], y[1], y[2], y[3]);
        return y;
    }

    // TODO FIX BELOW
    static long ror(long value, long bits) {
        return ((((value & 0xFFFFFFFFL) >> (bits & 0xFFFFFFFFL)) & 0xFFFFFFFFL)
                | (((value & 0xFFFFFFFFL) << ((32 - (bits & 0xFFFFFFFFL)) & 0xFFFFFFFFL)) & 0xFFFFFFFFL)) & 0xFFFFFFFFL;
    }

    static long MIN(long x, long y) {
        return (x < y) ? x & 0xFFFFFFFFL : y & 0xFFFFFFFFL;
    }

    static long LOAD32H(int[] y, int offset) {
        return ((long) ((y)[0 + offset] & 255) << 24) | ((long) ((y)[1 + offset] & 255) << 16) |
                ((long) ((y)[2 + offset] & 255) << 8) | ((long) ((y)[3 + offset] & 255));

    }

    static void STORE64H(long x, int[] y) {
        y[0 + 56] = (byte) (((x & 0xFFFFFFFFL) >> 56) & 0xFF);
        y[1 + 56] = (byte) (((x & 0xFFFFFFFFL) >> 48) & 0xFF);
        y[2 + 56] = (byte) (((x & 0xFFFFFFFFL) >> 40) & 0xFF);
        y[3 + 56] = (byte) (((x & 0xFFFFFFFFL) >> 32) & 0xFF);
        y[4 + 56] = (byte) (((x & 0xFFFFFFFFL) >> 24) & 0xFF);
        y[5 + 56] = (byte) (((x & 0xFFFFFFFFL) >> 16) & 0xFF);
        y[6 + 56] = (byte) (((x & 0xFFFFFFFFL) >> 8) & 0xFF);
        y[7 + 56] = (byte) ((x & 0xFFFFFFFFL) & 0xFF);
        // System.out.printf("y %02x %02x %02x %02x %02x %02x %02x %02x\n", y[56],
        // y[57], y[58], y[59], y[60], y[61], y[62], y[63]);

    }

    // int
    static long Ch(long x, long y, long z) {
        // System.out.printf("%02x %02x %02x ", x, y, z);
        System.out.printf("Ch: %02x\n",
                ((z & 0xFFFFFFFFL)
                        ^ (((x & 0xFFFFFFFFL) & (((y & 0xFFFFFFFFL) ^ (z & 0xFFFFFFFFL)) & 0xFFFFFFFFL)) & 0xFFFFFFFFL))
                        & 0xFFFFFFFFL);
        return ((z & 0xFFFFFFFFL)
                ^ (((x & 0xFFFFFFFFL) & (((y & 0xFFFFFFFFL) ^ (z & 0xFFFFFFFFL)) & 0xFFFFFFFFL)) & 0xFFFFFFFFL))
                & 0xFFFFFFFFL;
    }

    // int
    static long Maj(long x, long y, long z) {
        return ((((((x & 0xFFFFFFFFL) | (y & 0xFFFFFFFFL)) & 0xFFFFFFFFL) & (z & 0xFFFFFFFFL)) & 0xFFFFFFFFL)
                | (((x & 0xFFFFFFFFL) & (y & 0xFFFFFFFFL)) & 0xFFFFFFFFL)) & 0xFFFFFFFFL;
    }

    static long SS(long x, long n) {
        // System.out.printf("%02x %02x ", x, n);
        // System.out.printf("SS: %02x\n", (ror((x & 0xFFFFFFFFL), (n & 0xFFFFFFFFL)) &
        // 0xFFFFFFFFL) & 0xFFFFFFFFL);
        return ror((x & 0xFFFFFFFFL), (n & 0xFFFFFFFFL)) & 0xFFFFFFFFL;
    }

    static long R(long x, long n) {
        // System.out.printf("R: %02x\n", (((x & 0xFFFFFFFFL) & 0xFFFFFFFFL) >> (n &
        // 0xFFFFFFFFL)) & 0xFFFFFFFFL);
        return (((x & 0xFFFFFFFFL) & 0xFFFFFFFFL) >> (n & 0xFFFFFFFFL)) & 0xFFFFFFFFL;
    }

    static long Sigma0(long x) {
        // System.out.printf("Sig0: %02x ",
        // ((SS(x & 0xFFFFFFFFL, 2) & 0xFFFFFFFFL)
        // ^ (SS(x & 0xFFFFFFFFL, 13) & 0xFFFFFFFFL)
        // ^ (SS(x & 0xFFFFFFFFL, 22) & 0xFFFFFFFFL)) & 0xFFFFFFFFL);
        return (((SS(x & 0xFFFFFFFFL, 2) & 0xFFFFFFFFL)
                ^ (SS(x & 0xFFFFFFFFL, 13) & 0xFFFFFFFFL) & 0xFFFFFFFFL)
                ^ (SS(x & 0xFFFFFFFFL, 22) & 0xFFFFFFFFL)) & 0xFFFFFFFFL;
    }

    static long Sigma1(long x) {
        // System.out.printf("Sig1: %02x\n",
        // ((SS(x & 0xFFFFFFFFL, 6) & 0xFFFFFFFFL)
        // ^ (SS(x & 0xFFFFFFFFL, 11) & 0xFFFFFFFFL)
        // ^ (SS(x & 0xFFFFFFFFL, 25) & 0xFFFFFFFFL)) & 0xFFFFFFFFL);
        return ((((SS(x & 0xFFFFFFFFL, 6) & 0xFFFFFFFFL) ^ (SS(x & 0xFFFFFFFFL, 11) & 0xFFFFFFFFL)) & 0xFFFFFFFFL)
                ^ (SS(x & 0xFFFFFFFFL, 25) & 0xFFFFFFFFL)) & 0xFFFFFFFFL;
    }

    static long Gamma0(long x) {
        // System.out.printf("Gam0: %02x\n",
        // ((SS(x & 0xFFFFFFFFL, 7) & 0xFFFFFFFFL) ^ (SS(x & 0xFFFFFFFFL, 18) &
        // 0xFFFFFFFFL)
        // ^ (R(x & 0xFFFFFFFFL, 3) & 0xFFFFFFFFL)) & 0xFFFFFFFFL);
        return ((((SS(x & 0xFFFFFFFFL, 7) & 0xFFFFFFFFL) ^ (SS(x & 0xFFFFFFFFL, 18) & 0xFFFFFFFFL)) & 0xFFFFFFFFL)
                ^ (R(x & 0xFFFFFFFFL, 3) & 0xFFFFFFFFL)) & 0xFFFFFFFFL;
    }

    static long Gamma1(long x) {

        // System.out.printf("Gam1: %02x\n",
        // ((SS(x & 0xFFFFFFFFL, 17) & 0xFFFFFFFFL) ^ (SS(x & 0xFFFFFFFFL, 19) &
        // 0xFFFFFFFFL)
        // ^ (R(x & 0xFFFFFFFFL, 10) & 0xFFFFFFFFL)) & 0xFFFFFFFFL);
        return ((((SS(x & 0xFFFFFFFFL, 17) & 0xFFFFFFFFL)
                ^ (SS(x & 0xFFFFFFFFL, 19) & 0xFFFFFFFFL)) & 0xFFFFFFFFL)
                ^ (R(x & 0xFFFFFFFFL, 10) & 0xFFFFFFFFL)) & 0xFFFFFFFFL;
    }

    static long[] Sha256Round(long[] S, int i, long[] W) {
        // for (i = 0; i < 8; i++) {
        // System.out.printf("S %02x\n", S[i]);
        // }
        System.out.printf("W %02x ", W[i]);
        System.out.printf("S7 %02x\n",
                ((((((((((S[7] & 0xFFFFFFFFL) + (Sigma1(S[4] & 0xFFFFFFFFL) & 0xFFFFFFFFL)) & 0xFFFFFFFFL)
                        + (Ch(S[4] & 0xFFFFFFFFL, S[5] & 0xFFFFFFFFL, S[6] & 0xFFFFFFFFL) & 0xFFFFFFFFL)) & 0xFFFFFFFFL)
                        + (K[i] & 0xFFFFFFFFL)) & 0xFFFFFFFFL) + (W[i] & 0xFFFFFFFFL)) & 0xFFFFFFFFL)) & 0xFFFFFFFFL);
        long t0 = ((((((((((S[7] & 0xFFFFFFFFL) + (Sigma1(S[4] & 0xFFFFFFFFL) & 0xFFFFFFFFL)) & 0xFFFFFFFFL)
                + (Ch(S[4] & 0xFFFFFFFFL, S[5] & 0xFFFFFFFFL, S[6] & 0xFFFFFFFFL) & 0xFFFFFFFFL)) & 0xFFFFFFFFL)
                + (K[i] & 0xFFFFFFFFL)) & 0xFFFFFFFFL) + (W[i] & 0xFFFFFFFFL)) & 0xFFFFFFFFL)) & 0xFFFFFFFFL;
        long t1 = ((Sigma0(S[0] & 0xFFFFFFFFL) & 0xFFFFFFFFL)
                + (Maj(S[0] & 0xFFFFFFFFL, S[1] & 0xFFFFFFFFL, S[2] & 0xFFFFFFFFL) & 0xFFFFFFFFL))
                & 0xFFFFFFFFL;
        System.out.printf("T1 T0 %02x %02x\n", t1, t0);
        S[3] += t0 & 0xFFFFFFFFL;
        S[7] = ((t0 & 0xFFFFFFFFL) + (t1 & 0xFFFFFFFFL)) & 0xFFFFFFFFL;

        return S;
    }

    static void TransformFunction(Sha256Context Context, int[] Buffer) {
        long[] S = new long[8];
        long[] W = new long[64];
        long t;
        int i;

        // Copy state into S
        for (i = 0; i < 8; i++) {
            S[i] = Context.state[i] & 0xFFFFFFFFL;
        }

        // Copy the state into 512-bits into W[0..15]
        for (i = 0; i < 16; i++) {
            W[i] = LOAD32H(Buffer, 4 * i) & 0xFFFFFFFFL;
            // System.out.printf("EW %02x\n", W[i]);
        }
        // W[15] = 0x28;
        for (i = 0; i < 64; i++) {
            // System.out.printf("W %02x\n", W[i]);
        }
        // Fill W[16..63]
        for (i = 16; i < 64; i++) {
            W[i] = (((((Gamma1(W[i - 2] & 0xFFFFFFFFL) + (W[i - 7] & 0xFFFFFFFFL)) & 0xFFFFFFFFL)
                    + Gamma0(W[i - 15] & 0xFFFFFFFFL)) & 0xFFFFFFFFL)
                    + (W[i - 16] & 0xFFFFFFFFL))
                    & 0xFFFFFFFFL;
        }
        for (i = 0; i < 64; i++) {
            // System.out.printf("WW %02x\n", W[i] & 0xFFFFFFFFL);
        }

        // Compress
        for (i = 0; i < 64; i++) {
            S = Sha256Round(S, i, W);
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
            Context.state[i] = ((Context.state[i] & 0xFFFFFFFFL) + (S[i] & 0xFFFFFFFFL)) & 0XFFFFFFFFL;
        }
    }

    static void Sha256Initialise(Sha256Context Context) {
        Context.curlen = 0;
        Context.length = 0;
        Context.state[0] = 0x6A09E667L;
        Context.state[1] = 0xBB67AE85L;
        Context.state[2] = 0x3C6EF372L;
        Context.state[3] = 0xA54FF53AL;
        Context.state[4] = 0x510E527FL;
        Context.state[5] = 0x9B05688CL;
        Context.state[6] = 0x1F83D9ABL;
        Context.state[7] = 0x5BE0CD19L;

    }

    static void Sha256Update(Sha256Context Context, int[] Buffer, long BufferSize) {
        long n;
        while (BufferSize > 0) {
            if (Context.curlen == 0 && BufferSize >= BLOCK_SIZE) {

                TransformFunction(Context, Buffer);
                Context.length += BLOCK_SIZE * 8;
                Buffer = shiftBuffer(Buffer, BLOCK_SIZE);

                BufferSize -= BLOCK_SIZE;
            } else {
                n = MIN((int) BufferSize, BLOCK_SIZE - Context.curlen) & 0xFFFFFFFFL;
                System.arraycopy(Buffer, 0, Context.buf, Context.curlen, (int) (n & 0xFFFFFFFFL));
                Context.curlen += n;
                Buffer = shiftBuffer(Buffer, (int) (n & 0xFFFFFFFFL));

                BufferSize -= n;
                if (Context.curlen == BLOCK_SIZE) {
                    TransformFunction(Context, Context.buf);
                    Context.length += 8 * BLOCK_SIZE;
                    Context.curlen = 0;
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

    static void Sha256Finalise(Sha256Context Context, SHA256_HASH Digest) {
        int i;

        if (Context.curlen >= Context.buf.length) {
            return;
        }

        // Increase the length of the message
        Context.length += Context.curlen * 8;

        // Append the '1' bit
        Context.buf[(int) Context.curlen++] = (0x80 & 0xFF);

        // if the length is currently above 56 bytes we append zeros
        // then compress. Then we can fall back to padding zeros and length
        // encoding like normal.
        if (Context.curlen > 56) {
            while (Context.curlen < 64) {
                Context.buf[(int) Context.curlen++] = 0 & 0xFF;
            }
            TransformFunction(Context, Context.buf);
            Context.curlen = 0;
        }

        // Pad up to 56 bytes of zeroes
        while (Context.curlen < 56) {
            Context.buf[(int) Context.curlen++] = (byte) 0 & 0xFF;
        }

        // Store length
        // STORE64H(Context.length, Context.buf + 56);
        // System.out.println(Context.length);
        // STORE64H(Context.length, java.util.Arrays.copyOfRange(Context.buf, 56));

        STORE64H(Context.length, Context.buf);
        for (int j : Context.buf) {
            // System.out.printf("SUB: %02x\n", j);
        }
        TransformFunction(Context, Context.buf);

        // Copy output
        for (i = 0; i < 8; i++) {

            // System.out.printf("BD: %02x%02x%02x%02x\n",
            // Digest.bytes[0 + 4 * i],
            // Digest.bytes[1 + 4 * i],
            // Digest.bytes[2 + 4 * i],
            // Digest.bytes[3 + 4 * i]);
            // System.out.printf("State: %02x\n", Context.state[i]);
            int[] y = STORE32H(Context.state[i] & 0xFFFFFFFFL, Digest.bytes, 4 * i);
            Digest.bytes[4 * i] = y[4 * i];
            Digest.bytes[1 + 4 * i] = y[1 + 4 * i];
            Digest.bytes[2 + 4 * i] = y[2 + 4 * i];
            Digest.bytes[3 + 4 * i] = y[3 + 4 * i];
            // System.out.printf("DB: %02x%02x%02x%02x\n",
            // Digest.bytes[0 + 4 * i],
            // Digest.bytes[1 + 4 * i],
            // Digest.bytes[2 + 4 * i],
            // Digest.bytes[3 + 4 * i]);
        }
        // for (i = 0; i < Digest.bytes.length; i++) {
        // System.out.printf("Di %02x\n", Digest.bytes[i]);
        // }
    }

    static int[] sha256(int[] data, long datalen, int[] out, long outlen) {
        long sz;
        Sha256Context ctx = new Sha256Context();
        SHA256_HASH hash = new SHA256_HASH(SHA256_HASH_SIZE);

        Sha256Initialise(ctx);

        Sha256Update(ctx, data, datalen);

        // for (int i = 0; i < data.length; i++) {
        // System.out.printf("DAT %02x\n", data[i]);
        // }
        // for (int i = 0; i < ctx.state.length; i++) {
        // System.out.printf("ST %02x\n", ctx.state[i]);
        // }
        for (int i = 0; i < ctx.buf.length; i++) {
            // System.out.printf("BU %02x\n", ctx.buf[i]);
        }
        Sha256Finalise(ctx, hash);

        sz = (outlen > SHA256_HASH_SIZE) ? SHA256_HASH_SIZE : outlen;
        for (int i = 0; i < sz; i++) {
            out[i] = hash.bytes[i] & 0xFF;
        }
        return out;
        // return memcpy(out, hash.bytes, sz);
    }

    // Library implementation
    public static byte[] computeHMAC(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "HmacSHA256");
            mac.init(secretKeySpec);
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException("HMAC-SHA256 computation failed", e);
        }
    }

    public static void main(String[] args) {

        // byte[] test = new byte[4];
        // int tval = 0x4f25;
        // STORE32H(tval, test);
        // for(int i = 0; i < 4;i++){
        // System.out.printf("--%02x\n", test[i]);
        // }

        byte[] key = "keykey".getBytes();
        byte[] message = "hello".getBytes(StandardCharsets.US_ASCII);
        byte[] hmac = computeHMAC(key, message);
        // byte[] out = new byte[32];

        int[] out = new int[32];

        // for (byte b : hmac) {
        // System.out.printf("%02x", b);
        // }
        int[] m = new int[message.length];
        for (int i = 0; i < message.length; i++) {
            m[i] = message[i];
        }
        sha256(m, message.length, out, 32);
        for (int i = 0; i < out.length; i++) {
            System.out.printf("%02x", out[i]);
        }
        System.out.println();
    }
}
