package org.ok.protocols;



import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class SHA256Test {
    
    @Test void testSHA256() {
        SHA256 sha256 = new SHA256();

        byte[] out = new byte[32];
        Block msg = new Block("This is a test");

        sha256.sha256(msg.getData(), out);

        Block expected = Block.fromHexString("c7be1ed902fb8dd4d48997c6452f5d7e509fbcdbe2808b16bcf4edce4c07d14e");

        assertEquals(expected, new Block(out));
    }
}
