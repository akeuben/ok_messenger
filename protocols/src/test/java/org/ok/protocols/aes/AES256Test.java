package org.ok.protocols.aes;

import org.junit.jupiter.api.Test;
import org.ok.protocols.Block;

import static org.junit.jupiter.api.Assertions.*;

public class AES256Test {

    @Test
    void TestZeroMessageEncrypt() {
        AESKey[] knownKeys = new AESKey[] {
                AESKey.fromHexString("c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558"),
                AESKey.fromHexString("28d46cffa158533194214a91e712fc2b45b518076675affd910edeca5f41ac64"),
                AESKey.fromHexString("c1cc358b449909a19436cfbb3f852ef8bcb5ed12ac7058325f56e6099aab1a1c"),
                AESKey.fromHexString("984ca75f4ee8d706f46c2d98c0bf4a45f5b00d791c2dfeb191b5ed8e420fd627"),
                AESKey.fromHexString("b43d08a447ac8609baadae4ff12918b9f68fc1653f1269222f123981ded7a92f"),
                AESKey.fromHexString("1d85a181b54cde51f0e098095b2962fdc93b51fe9b88602b3f54130bf76a5bd9"),
                AESKey.fromHexString("dc0eba1f2232a7879ded34ed8428eeb8769b056bbaf8ad77cb65c3541430b4cf"),
                AESKey.fromHexString("f8be9ba615c5a952cabbca24f68f8593039624d524c816acda2c9183bd917cb9"),
                AESKey.fromHexString("797f8b3d176dac5b7e34a2d539c4ef367a16f8635f6264737591c5c07bf57a3e"),
                AESKey.fromHexString("6838d40caf927749c13f0329d331f448e202c73ef52c5f73a37ca635d4c47707"),
                AESKey.fromHexString("ccd1bc3c659cd3c59bc437484e3c5c724441da8d6e90ce556cd57d0752663bbc"),
                AESKey.fromHexString("13428b5e4c005e0636dd338405d173ab135dec2a25c22c5df0722d69dcc43887"),
                AESKey.fromHexString("07eb03a08d291d1b07408bf3512ab40c91097ac77461aad4bb859647f74f00ee"),
                AESKey.fromHexString("90143ae20cd78c5d8ebdd6cb9dc1762427a96c78c639bccc41a61424564eafe1"),
                AESKey.fromHexString("b7a5794d52737475d53d5a377200849be0260a67a2b22ced8bbef12882270d07"),
                AESKey.fromHexString("fca02f3d5011cfc5c1e23165d413a049d4526a991827424d896fe3435e0bf68e"),
                AESKey.fromHexString("c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558"),
                AESKey.fromHexString("28d46cffa158533194214a91e712fc2b45b518076675affd910edeca5f41ac64"),
                AESKey.fromHexString("c1cc358b449909a19436cfbb3f852ef8bcb5ed12ac7058325f56e6099aab1a1c"),
                AESKey.fromHexString("984ca75f4ee8d706f46c2d98c0bf4a45f5b00d791c2dfeb191b5ed8e420fd627"),
                AESKey.fromHexString("b43d08a447ac8609baadae4ff12918b9f68fc1653f1269222f123981ded7a92f"),
                AESKey.fromHexString("1d85a181b54cde51f0e098095b2962fdc93b51fe9b88602b3f54130bf76a5bd9"),
                AESKey.fromHexString("dc0eba1f2232a7879ded34ed8428eeb8769b056bbaf8ad77cb65c3541430b4cf"),
                AESKey.fromHexString("f8be9ba615c5a952cabbca24f68f8593039624d524c816acda2c9183bd917cb9"),
                AESKey.fromHexString("797f8b3d176dac5b7e34a2d539c4ef367a16f8635f6264737591c5c07bf57a3e"),
                AESKey.fromHexString("6838d40caf927749c13f0329d331f448e202c73ef52c5f73a37ca635d4c47707"),
                AESKey.fromHexString("ccd1bc3c659cd3c59bc437484e3c5c724441da8d6e90ce556cd57d0752663bbc"),
                AESKey.fromHexString("13428b5e4c005e0636dd338405d173ab135dec2a25c22c5df0722d69dcc43887"),
                AESKey.fromHexString("07eb03a08d291d1b07408bf3512ab40c91097ac77461aad4bb859647f74f00ee"),
                AESKey.fromHexString("90143ae20cd78c5d8ebdd6cb9dc1762427a96c78c639bccc41a61424564eafe1"),
                AESKey.fromHexString("b7a5794d52737475d53d5a377200849be0260a67a2b22ced8bbef12882270d07"),
                AESKey.fromHexString("fca02f3d5011cfc5c1e23165d413a049d4526a991827424d896fe3435e0bf68e"),
        };
        Block msg = Block.fromHexString("00000000000000000000000000000000");

        Block[] expectedCiphertexts = new Block[] {
                Block.fromHexString("46f2fb342d6f0ab477476fc501242c5f"),
                Block.fromHexString("4bf3b0a69aeb6657794f2901b1440ad4"),
                Block.fromHexString("352065272169abf9856843927d0674fd"),
                Block.fromHexString("4307456a9e67813b452e15fa8fffe398"),
                Block.fromHexString("4663446607354989477a5c6f0f007ef4"),
                Block.fromHexString("531c2c38344578b84d50b3c917bbb6e1"),
                Block.fromHexString("fc6aec906323480005c58e7e1ab004ad"),
                Block.fromHexString("a3944b95ca0b52043584ef02151926a8"),
                Block.fromHexString("a74289fe73a4c123ca189ea1e1b49ad5"),
                Block.fromHexString("b91d4ea4488644b56cf0812fa7fcf5fc"),
                Block.fromHexString("304f81ab61a80c2e743b94d5002a126b"),
                Block.fromHexString("649a71545378c783e368c9ade7114f6c"),
                Block.fromHexString("47cb030da2ab051dfc6c4bf6910d12bb"),
                Block.fromHexString("798c7c005dee432b2c8ea5dfa381ecc3"),
                Block.fromHexString("637c31dc2591a07636f646b72daabbe7"),
                Block.fromHexString("179a49c712154bbffbe6e7a84a18e220"),
                Block.fromHexString("46f2fb342d6f0ab477476fc501242c5f"),
                Block.fromHexString("4bf3b0a69aeb6657794f2901b1440ad4"),
                Block.fromHexString("352065272169abf9856843927d0674fd"),
                Block.fromHexString("4307456a9e67813b452e15fa8fffe398"),
                Block.fromHexString("4663446607354989477a5c6f0f007ef4"),
                Block.fromHexString("531c2c38344578b84d50b3c917bbb6e1"),
                Block.fromHexString("fc6aec906323480005c58e7e1ab004ad"),
                Block.fromHexString("a3944b95ca0b52043584ef02151926a8"),
                Block.fromHexString("a74289fe73a4c123ca189ea1e1b49ad5"),
                Block.fromHexString("b91d4ea4488644b56cf0812fa7fcf5fc"),
                Block.fromHexString("304f81ab61a80c2e743b94d5002a126b"),
                Block.fromHexString("649a71545378c783e368c9ade7114f6c"),
                Block.fromHexString("47cb030da2ab051dfc6c4bf6910d12bb"),
                Block.fromHexString("798c7c005dee432b2c8ea5dfa381ecc3"),
                Block.fromHexString("637c31dc2591a07636f646b72daabbe7"),
                Block.fromHexString("179a49c712154bbffbe6e7a84a18e220"),
        };

        for(int i = 0; i < knownKeys.length; i++) {
            Block expectedCiphertext = expectedCiphertexts[i];
            AESKey key = knownKeys[i];

            Block actualCiphertext = new AES256().encrypt(msg, key);

            assertEquals(expectedCiphertext, actualCiphertext);
        }
    }

    @Test
    void TestZeroMessageDecrypt() {
        AESKey[] knownKeys = new AESKey[] {
                AESKey.fromHexString("c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558"),
                AESKey.fromHexString("28d46cffa158533194214a91e712fc2b45b518076675affd910edeca5f41ac64"),
                AESKey.fromHexString("c1cc358b449909a19436cfbb3f852ef8bcb5ed12ac7058325f56e6099aab1a1c"),
                AESKey.fromHexString("984ca75f4ee8d706f46c2d98c0bf4a45f5b00d791c2dfeb191b5ed8e420fd627"),
                AESKey.fromHexString("b43d08a447ac8609baadae4ff12918b9f68fc1653f1269222f123981ded7a92f"),
                AESKey.fromHexString("1d85a181b54cde51f0e098095b2962fdc93b51fe9b88602b3f54130bf76a5bd9"),
                AESKey.fromHexString("dc0eba1f2232a7879ded34ed8428eeb8769b056bbaf8ad77cb65c3541430b4cf"),
                AESKey.fromHexString("f8be9ba615c5a952cabbca24f68f8593039624d524c816acda2c9183bd917cb9"),
                AESKey.fromHexString("797f8b3d176dac5b7e34a2d539c4ef367a16f8635f6264737591c5c07bf57a3e"),
                AESKey.fromHexString("6838d40caf927749c13f0329d331f448e202c73ef52c5f73a37ca635d4c47707"),
                AESKey.fromHexString("ccd1bc3c659cd3c59bc437484e3c5c724441da8d6e90ce556cd57d0752663bbc"),
                AESKey.fromHexString("13428b5e4c005e0636dd338405d173ab135dec2a25c22c5df0722d69dcc43887"),
                AESKey.fromHexString("07eb03a08d291d1b07408bf3512ab40c91097ac77461aad4bb859647f74f00ee"),
                AESKey.fromHexString("90143ae20cd78c5d8ebdd6cb9dc1762427a96c78c639bccc41a61424564eafe1"),
                AESKey.fromHexString("b7a5794d52737475d53d5a377200849be0260a67a2b22ced8bbef12882270d07"),
                AESKey.fromHexString("fca02f3d5011cfc5c1e23165d413a049d4526a991827424d896fe3435e0bf68e"),
                AESKey.fromHexString("c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558"),
                AESKey.fromHexString("28d46cffa158533194214a91e712fc2b45b518076675affd910edeca5f41ac64"),
                AESKey.fromHexString("c1cc358b449909a19436cfbb3f852ef8bcb5ed12ac7058325f56e6099aab1a1c"),
                AESKey.fromHexString("984ca75f4ee8d706f46c2d98c0bf4a45f5b00d791c2dfeb191b5ed8e420fd627"),
                AESKey.fromHexString("b43d08a447ac8609baadae4ff12918b9f68fc1653f1269222f123981ded7a92f"),
                AESKey.fromHexString("1d85a181b54cde51f0e098095b2962fdc93b51fe9b88602b3f54130bf76a5bd9"),
                AESKey.fromHexString("dc0eba1f2232a7879ded34ed8428eeb8769b056bbaf8ad77cb65c3541430b4cf"),
                AESKey.fromHexString("f8be9ba615c5a952cabbca24f68f8593039624d524c816acda2c9183bd917cb9"),
                AESKey.fromHexString("797f8b3d176dac5b7e34a2d539c4ef367a16f8635f6264737591c5c07bf57a3e"),
                AESKey.fromHexString("6838d40caf927749c13f0329d331f448e202c73ef52c5f73a37ca635d4c47707"),
                AESKey.fromHexString("ccd1bc3c659cd3c59bc437484e3c5c724441da8d6e90ce556cd57d0752663bbc"),
                AESKey.fromHexString("13428b5e4c005e0636dd338405d173ab135dec2a25c22c5df0722d69dcc43887"),
                AESKey.fromHexString("07eb03a08d291d1b07408bf3512ab40c91097ac77461aad4bb859647f74f00ee"),
                AESKey.fromHexString("90143ae20cd78c5d8ebdd6cb9dc1762427a96c78c639bccc41a61424564eafe1"),
                AESKey.fromHexString("b7a5794d52737475d53d5a377200849be0260a67a2b22ced8bbef12882270d07"),
                AESKey.fromHexString("fca02f3d5011cfc5c1e23165d413a049d4526a991827424d896fe3435e0bf68e"),
        };
        Block expectedMsg = Block.fromHexString("00000000000000000000000000000000");

        Block[] ciphertexts = new Block[] {
                Block.fromHexString("46f2fb342d6f0ab477476fc501242c5f"),
                Block.fromHexString("4bf3b0a69aeb6657794f2901b1440ad4"),
                Block.fromHexString("352065272169abf9856843927d0674fd"),
                Block.fromHexString("4307456a9e67813b452e15fa8fffe398"),
                Block.fromHexString("4663446607354989477a5c6f0f007ef4"),
                Block.fromHexString("531c2c38344578b84d50b3c917bbb6e1"),
                Block.fromHexString("fc6aec906323480005c58e7e1ab004ad"),
                Block.fromHexString("a3944b95ca0b52043584ef02151926a8"),
                Block.fromHexString("a74289fe73a4c123ca189ea1e1b49ad5"),
                Block.fromHexString("b91d4ea4488644b56cf0812fa7fcf5fc"),
                Block.fromHexString("304f81ab61a80c2e743b94d5002a126b"),
                Block.fromHexString("649a71545378c783e368c9ade7114f6c"),
                Block.fromHexString("47cb030da2ab051dfc6c4bf6910d12bb"),
                Block.fromHexString("798c7c005dee432b2c8ea5dfa381ecc3"),
                Block.fromHexString("637c31dc2591a07636f646b72daabbe7"),
                Block.fromHexString("179a49c712154bbffbe6e7a84a18e220"),
                Block.fromHexString("46f2fb342d6f0ab477476fc501242c5f"),
                Block.fromHexString("4bf3b0a69aeb6657794f2901b1440ad4"),
                Block.fromHexString("352065272169abf9856843927d0674fd"),
                Block.fromHexString("4307456a9e67813b452e15fa8fffe398"),
                Block.fromHexString("4663446607354989477a5c6f0f007ef4"),
                Block.fromHexString("531c2c38344578b84d50b3c917bbb6e1"),
                Block.fromHexString("fc6aec906323480005c58e7e1ab004ad"),
                Block.fromHexString("a3944b95ca0b52043584ef02151926a8"),
                Block.fromHexString("a74289fe73a4c123ca189ea1e1b49ad5"),
                Block.fromHexString("b91d4ea4488644b56cf0812fa7fcf5fc"),
                Block.fromHexString("304f81ab61a80c2e743b94d5002a126b"),
                Block.fromHexString("649a71545378c783e368c9ade7114f6c"),
                Block.fromHexString("47cb030da2ab051dfc6c4bf6910d12bb"),
                Block.fromHexString("798c7c005dee432b2c8ea5dfa381ecc3"),
                Block.fromHexString("637c31dc2591a07636f646b72daabbe7"),
                Block.fromHexString("179a49c712154bbffbe6e7a84a18e220"),
        };

        for(int i = 0; i < knownKeys.length; i++) {
            Block ciphertext = ciphertexts[i];
            AESKey key = knownKeys[i];

            Block actualMsg = new AES256().decrypt(ciphertext, key);

            assertEquals(expectedMsg, actualMsg);
        }
    }

    @Test
    void Enc_AddRoundKeyTest() {
        Block state = new Block(128/8, new byte[] {
                0x11,0x12,0x13,0x14,
                0x21,0x22,0x23,0x24,
                0x31,0x32,0x33,0x34,
                0x41,0x42,0x43,0x44,
        });

        Block roundKey = new Block(128/8, new byte[] {
                0x21,0x22,0x23,0x24,
                0x31,0x32,0x33,0x34,
                0x41,0x42,0x43,0x44,
                0x11,0x12,0x13,0x14,
        });

        Block expectedNewState = new Block(128/8, new byte[] {
                0x30, 0x30, 0x30, 0x30,
                0x10, 0x10, 0x10, 0x10,
                0x70, 0x70, 0x70, 0x70,
                0x50, 0x50, 0x50, 0x50,
        });

        Block actualNewState = AES256.Enc_AddRoundKey(state, roundKey);

        assertEquals(expectedNewState, actualNewState);
    }

    @Test
    void Enc_SubBytesTest() {
        Block state = new Block(128/8, new byte[] {
                0x11,0x12,0x13,0x14,
                0x21,0x22,0x23,0x24,
                0x31,0x32,0x33,0x34,
                0x41,0x42,0x43,0x44,
        });

        Block expectedNewState = new Block(128/8, new byte[] {
                (byte) 0x82, (byte) 0xc9, (byte) 0x7d, (byte) 0xfa,
                (byte) 0xfd, (byte) 0x93, (byte) 0x26, (byte) 0x36,
                (byte) 0xc7, (byte) 0x23, (byte) 0xc3, (byte) 0x18,
                (byte) 0x83, (byte) 0x2c, (byte) 0x1a, (byte) 0x1b,
        });

        Block actualNewState = AES.Enc_SubBytes(state);

        assertEquals(expectedNewState, actualNewState);
    }

    @Test
    public void Enc_ShiftRowsTest() {
        Block state = new Block(128/8, new byte[] {
                0x11,0x12,0x13,0x14,
                0x21,0x22,0x23,0x24,
                0x31,0x32,0x33,0x34,
                0x41,0x42,0x43,0x44,
        });

        // Column major order
        Block expectedNewState = new Block(128/8, new byte[] {
                0x11,0x22,0x33,0x44,
                0x21,0x32,0x43,0x14,
                0x31,0x42,0x13,0x24,
                0x41,0x12,0x23,0x34,
        });

        assertEquals(AES.Enc_ShiftRows(state), expectedNewState);
    }

    @Test
    public void Enc_MixColumnsTest() {
        Block state = new Block(128/8, new byte[] {
                (byte) 0x63, (byte) 0x47, (byte) 0xa2, (byte) 0xf0,
                (byte) 0xf2, (byte) 0x0a, (byte) 0x22, (byte) 0x5c,
                (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01,
                (byte) 0xc6, (byte) 0xc6, (byte) 0xc6, (byte) 0xc6,
        });

        Block expectedNewState = new Block(128/8, new byte[] {
                (byte) 0x5d, (byte) 0xe0, (byte) 0x70, (byte) 0xbb,
                (byte) 0x9f, (byte) 0xdc, (byte) 0x58, (byte) 0x9d,
                (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01,
                (byte) 0xc6, (byte) 0xc6, (byte) 0xc6, (byte) 0xc6,
        });

        Block actualNewState = AES.Enc_MixColumns(state);

        assertEquals(expectedNewState, actualNewState);
    }
}
