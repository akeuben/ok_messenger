package org.ok.protocols.aes;

import org.ok.protocols.Block;

public class AES256 extends AES {

    private static final int h = 14;

    @Override
    public Block encrypt(Block block, AESKey key) {
        assert key.getSizeBits() == 256;
        assert block.getSizeBits() == 128;

        Block state = block;
        for(int i = 0 ; i < h; i++) {

        }

        return null;
    }

    @Override
    public Block decrypt(Block block, AESKey key) {
        return null;
    }
}
