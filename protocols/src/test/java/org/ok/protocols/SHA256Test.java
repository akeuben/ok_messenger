package org.ok.protocols;



import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class SHA256Test {
    
    @Test void testConstructor() {
        SHA256 sha256 = new SHA256();
        assertEquals(0, sha256.sha256(new int[]{0x9382,0x456}, new int[]{0x12,12}));
    }
}
