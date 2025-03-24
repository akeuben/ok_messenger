package org.ok.math;

public class GF256 {
    private static final int MODULO = 0x11B; // AES standard irreducible polynomial

    private static final int[][] table = new int[256][256];

    static {
        for(int i = 0; i < 256; i++) {
            for(int j = 0; j < 256; j++) {
                table[i][j] = multiplyInsecure(i, j);
            }
        }
    }

    public static int multiplyInsecure(int a, int b) {
        int result = 0;

        while (b > 0) {
            if ((b & 1) != 0) {  // If LSB of b is set, add a to result
                result ^= a; // Addition in GF(2) is XOR
            }

            boolean highBitSet = (a & 0x80) != 0; // Check if MSB is set
            a <<= 1; // Multiply by x (shift left)

            if (highBitSet) {
                a ^= MODULO; // Reduce modulo the irreducible polynomial
            }

            b >>= 1; // Move to next bit of b
        }

        return result & 0xFF; // Ensure 8-bit result
    }

    public static int multiply(int a, int b) {
        while(a < 0) a += 256;
        while(b < 0) b += 256;
        return table[a][b] & 0xFF;
    }

    public static void main(String[] args) {
        System.out.println("private static final byte[][] table = new byte[][] {");
        for(int i = 0; i < 256; i++) {
            System.out.print("new byte[] {");
            for(int j = 0; j < 256; j++) {
                System.out.print("(byte) " + multiply(i, j) + ",");
            }
            System.out.println("}");
        }
        System.out.println("}");

    }
}
