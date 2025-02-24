package org.ok.protocols.aes;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class AESKeyTest {

    @Test
    public void testSplitKey() {
        byte[] rawKey = new byte[] {
                0x11,0x12,0x13,0x14,
                0x21,0x22,0x23,0x24,
                0x31,0x32,0x33,0x34,
                0x41,0x42,0x43,0x44,
                0x11,0x12,0x13,0x14,
                0x21,0x22,0x23,0x24,
                0x31,0x32,0x33,0x34,
                0x41,0x42,0x43,0x44
        };

        AESKey key = new AESKey(rawKey);
        int[] split = key.split();

        assertEquals(split[0], 0x11121314);
        assertEquals(split[1], 0x21222324);
        assertEquals(split[2], 0x31323334);
        assertEquals(split[3], 0x41424344);
        assertEquals(split[4], 0x11121314);
        assertEquals(split[5], 0x21222324);
        assertEquals(split[6], 0x31323334);
        assertEquals(split[7], 0x41424344);
    }

    @Test
    public void KeyExpansionTestMin() {
        AESKey key = AESKey.fromHexString("0000000000000000000000000000000000000000000000000000000000000000");
        AESKey[] expectedKeys = new AESKey[]{
                AESKey.fromHexString("00000000000000000000000000000000"),
                AESKey.fromHexString("00000000000000000000000000000000"),
                AESKey.fromHexString("62636363626363636263636362636363"),
                AESKey.fromHexString("aafbfbfbaafbfbfbaafbfbfbaafbfbfb"),
                AESKey.fromHexString("6f6c6ccf0d0f0fac6f6c6ccf0d0f0fac"),
                AESKey.fromHexString("7d8d8d6ad77676917d8d8d6ad7767691"),
                AESKey.fromHexString("5354edc15e5be26d31378ea23c38810e"),
                AESKey.fromHexString("968a81c141fcf7503c717a3aeb070cab"),
                AESKey.fromHexString("9eaa8f28c0f16d45f1c6e3e7cdfe62e9"),
                AESKey.fromHexString("2b312bdf6acddc8f56bca6b5bdbbaa1e"),
                AESKey.fromHexString("6406fd52a4f79017553173f098cf1119"),
                AESKey.fromHexString("6dbba90b0776758451cad331ec71792f"),
                AESKey.fromHexString("e7b0e89c4347788b16760b7b8eb91a62"),
                AESKey.fromHexString("74ed0ba1739b7e252251ad14ce20d43b"),
                AESKey.fromHexString("10f80a1753bf729c45c979e7cb706385"),
        };

        for(int i = 0; i < 15; i++) {
            assertEquals(expectedKeys[i], key.getRoundKey(i));
        }
    }

    @Test
    public void KeyExpansionTestMax() {
        AESKey key = AESKey.fromHexString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
        AESKey[] expectedKeys = new AESKey[]{
                AESKey.fromHexString("ffffffffffffffffffffffffffffffff"),
                AESKey.fromHexString("ffffffffffffffffffffffffffffffff"),
                AESKey.fromHexString("e8e9e9e917161616e8e9e9e917161616"),
                AESKey.fromHexString("0fb8b8b8f04747470fb8b8b8f0474747"),
                AESKey.fromHexString("4a4949655d5f5f73b5b6b69aa2a0a08c"),
                AESKey.fromHexString("355858dcc51f1f9bcaa7a7233ae0e064"),
                AESKey.fromHexString("afa80ae5f2f755964741e30ce5e14380"),
                AESKey.fromHexString("eca0421129bf5d8ae318faa9d9f81acd"),
                AESKey.fromHexString("e60ab7d014fde24653bc014ab65d42ca"),
                AESKey.fromHexString("a2ec6e658b5333ef684bc946b1b3d38b"),
                AESKey.fromHexString("9b6c8a188f91685edc2d69146a702bde"),
                AESKey.fromHexString("a0bd9f782beeac9743a565d1f216b65a"),
                AESKey.fromHexString("fc22349173b35ccfaf9e35dbc5ee1e05"),
                AESKey.fromHexString("0695ed132d7b41846ede24559cc8920f"),
                AESKey.fromHexString("546d424f27de1e8088402b5b4dae355e"),
        };

        for(int i = 0; i < 15; i++) {
            assertEquals(expectedKeys[i], key.getRoundKey(i));
        }
    }

    @Test
    public void KeyExpansionTestInc() {
        AESKey key = AESKey.fromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        AESKey[] expectedKeys = new AESKey[]{
                AESKey.fromHexString("000102030405060708090a0b0c0d0e0f"),
                AESKey.fromHexString("101112131415161718191a1b1c1d1e1f"),
                AESKey.fromHexString("a573c29fa176c498a97fce93a572c09c"),
                AESKey.fromHexString("1651a8cd0244beda1a5da4c10640bade"),
                AESKey.fromHexString("ae87dff00ff11b68a68ed5fb03fc1567"),
                AESKey.fromHexString("6de1f1486fa54f9275f8eb5373b8518d"),
                AESKey.fromHexString("c656827fc9a799176f294cec6cd5598b"),
                AESKey.fromHexString("3de23a75524775e727bf9eb45407cf39"),
                AESKey.fromHexString("0bdc905fc27b0948ad5245a4c1871c2f"),
                AESKey.fromHexString("45f5a66017b2d387300d4d33640a820a"),
                AESKey.fromHexString("7ccff71cbeb4fe5413e6bbf0d261a7df"),
                AESKey.fromHexString("f01afafee7a82979d7a5644ab3afe640"),
                AESKey.fromHexString("2541fe719bf500258813bbd55a721c0a"),
                AESKey.fromHexString("4e5a6699a9f24fe07e572baacdf8cdea"),
                AESKey.fromHexString("24fc79ccbf0979e9371ac23c6d68de36"),
        };

        for(int i = 0; i < 15; i++) {
            assertEquals(expectedKeys[i], key.getRoundKey(i));
        }
    }
}
