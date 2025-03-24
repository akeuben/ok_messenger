package org.ok.protocols.aes;

import org.ok.protocols.Block;

public class AES256 extends AES {

    private static final int h = 14;

    public static Block encrypt(Block block, AESKey key) {
        assert key.getSizeBits() == 256;
        assert block.getSizeBits() == 128;

        Block state = block;

        state = Enc_AddRoundKey(state, key.getRoundKey(0));
        for (int i = 0; i < h - 1; i++) {
            state = Enc_SubBytes(state);
            state = Enc_ShiftRows(state);
            state = Enc_MixColumns(state);
            state = Enc_AddRoundKey(state, key.getRoundKey(i + 1));
        }
        state = Enc_SubBytes(state);
        state = Enc_ShiftRows(state);
        state = Enc_AddRoundKey(state, key.getRoundKey(h));

        return state;
    }

    public static Block decrypt(Block block, AESKey key) {
        assert key.getSizeBits() == 256;
        assert block.getSizeBits() == 128;

        Block state = block;

        state = Dec_AddRoundKey(state, key.getRoundKey(h));
        for(int i = h-1; i > 0; i--) {
            state = Dec_ShiftRows(state);
            state = Dec_SubBytes(state);
            state = Dec_AddRoundKey(state, key.getRoundKey(i));
            state = Dec_MixColumns(state);
        }
        state = Dec_ShiftRows(state);
        state = Dec_SubBytes(state);
        state = Dec_AddRoundKey(state, key.getRoundKey(0));

        return state;
    }
}
