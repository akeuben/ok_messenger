package org.ok.math;

public class GF256 {
    private static final int MODULO = 0x11B; // AES standard irreducible polynomial

    public static int multiply(int a, int b) {
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

    public static void main(String[] args) {
        int a = 0x57; // Example value (87 in decimal)
        int b = 0x83; // Example value (131 in decimal)

        int product = multiply(a, b);
        System.out.printf("Multiplication in GF(2^8): 0x%02X\n", product); // Expected: 0xC1
    }
}
