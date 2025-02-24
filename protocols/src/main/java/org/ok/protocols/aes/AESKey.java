package org.ok.protocols.aes;

import org.ok.protocols.Key;

import java.util.HexFormat;

public class AESKey extends Key {

    private static final int[] roundConstants256 = new int[] {
            0x01_00_00_00,  // Rcon[1]
            0x02_00_00_00,  // Rcon[2]
            0x04_00_00_00,  // Rcon[3]
            0x08_00_00_00,  // Rcon[4]
            0x10_00_00_00,  // Rcon[5]
            0x20_00_00_00,  // Rcon[6]
            0x40_00_00_00   // Rcon[7]
    };

    private int[] words;

    public AESKey(byte[] key) {
        super(key.length, key);
        assert key.length == 32 || key.length == 24 || key.length == 16;

        derive();
    }

    public AESKey(String key) {
        super(key.length(), key);
        assert key.length() == 32 || key.length() == 24 || key.length() == 16;

        derive();
    }

    public static AESKey fromHexString(String hexEncodedKey) {
        byte[] bytes = HexFormat.of().parseHex(hexEncodedKey);

        return new AESKey(bytes);
    }

    public int[] split() {
        int[] words = new int[getSizeBytes()/4];
        byte[] data = getData();

        for(int i = 0; i < getSizeBytes() / 4; i++) {
            words[i] = (((int) data[i * 4] & 0xFF) << 24) |
                    (((int) data[i * 4 + 1] & 0xFF) << 16) |
                    (((int) data[i * 4 + 2] & 0xFF) << 8) |
                    ((int) data[i * 4 + 3] & 0xFF);
        }

        return words;
    }

    public AESKey getRoundKey(int round) {
        long keyData1 = ((long) words[round * 4]) & 0xFFFFFFFFL;
        long keyData2 = ((long) words[round * 4 + 1]) & 0xFFFFFFFFL;
        long keyData3 = ((long) words[round * 4 + 2]) & 0xFFFFFFFFL;
        long keyData4 = ((long) words[round * 4 + 3]) & 0xFFFFFFFFL;

        return new AESKey(new byte[] {
                (byte) ((keyData1 & 0xFF000000L) >>> 24),
                (byte) ((keyData1 & 0x00FF0000L) >>> 16),
                (byte) ((keyData1 & 0x0000FF00L) >>> 8),
                (byte) ((keyData1 & 0x000000FFL)),
                (byte) ((keyData2 & 0xFF000000L) >>> 24),
                (byte) ((keyData2 & 0x00FF0000L) >>> 16),
                (byte) ((keyData2 & 0x0000FF00L) >>> 8),
                (byte) ((keyData2 & 0x000000FFL)),
                (byte) ((keyData3 & 0xFF000000L) >>> 24),
                (byte) ((keyData3 & 0x00FF0000L) >>> 16),
                (byte) ((keyData3 & 0x0000FF00L) >>> 8),
                (byte) ((keyData3 & 0x000000FFL)),
                (byte) ((keyData4 & 0xFF000000L) >>> 24),
                (byte) ((keyData4 & 0x00FF0000L) >>> 16),
                (byte) ((keyData4 & 0x0000FF00L) >>> 8),
                (byte) ((keyData4 & 0x000000FFL)),
        });
    }

    private void derive() {
        switch(getSizeBits()) {
            case 256: {
                derive256();
                return;
            }
            default: {
            }
        }
    }

    private int sub(int value) {
        int[] bytes = new int[] {
                ((value >>> 24) & 0xFF),
                ((value >>> 16) & 0xFF),
                ((value >>> 8) & 0xFF),
                ((value) & 0xFF),
        };

        for(int i = 0; i < 4; i++) {
            bytes[i] = AES.encryptionSTable[bytes[i] & 0xFF] & 0xFF;
            assert bytes[i] < 256;
        }

        long resultA = (((long) bytes[0]) << 24) ^ (((long) bytes[1]) << 16) ^ (((long) bytes[2]) << 8) ^ ((long) bytes[3]);
        long resultB = (((long) bytes[0]) << 24) | (((long) bytes[1]) << 16) | (((long) bytes[2]) << 8) | ((long) bytes[3]);

        assert resultA == resultB;

        return (int) (resultA);
    }

    private void derive256() {
        int[] originalWords = split();
        if(words == null)
            words = new int[60];

        // The original key has 8 words, and those are the first words to be used.
        for(int i = 0; i < 8; i++) {
            words[i] = originalWords[i];
        }

        for(int i = 8; i < 60; i++) {
            int temp = words[i-1];

            if(i % 8 == 0)
                temp = sub(Integer.rotateLeft(temp, 8)) ^ roundConstants256[i/8-1];
            else if(i % 8 == 4)
                temp = sub(temp);

            words[i] = words[i - 8] ^ temp;
        }
    }
}
