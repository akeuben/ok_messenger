package org.ok.protocols;

class Sha256Context {
    protected Long length;
    protected int[] state = new int[8];
    protected int curlen;
    protected byte[] buf = new byte[64];
};

class SHA256 {
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

    private int ror(int value, int bits) {
        return (((value) >> (bits)) | ((value) << (32 - (bits))));
    }

    private void store32H(int x, byte[] y) {
        y[0] = (byte) ((x >> 24) & 255);
        y[1] = (byte) ((x >> 16) & 255);
        y[2] = (byte) ((x >> 8) & 255);
        y[3] = (byte) (x & 255);
    }

    private int load32H(byte[] y) {
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

    void TransformFunction(Sha256Context Context, byte[][] Buffer) {
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
            W[i] = load32H(Buffer[i]);
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
}

public class HMAC256 {
    public HMAC256() {

    }

    public void testPrint() {
        System.out.println("HMAC printing");
    }
}
