package org.ok.math;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class GF256Test {

    @Test
    public void TestGF256() {
        assertEquals((byte) 0xc8, GF256.multiply(0xec, 0x3b));
    }
}
