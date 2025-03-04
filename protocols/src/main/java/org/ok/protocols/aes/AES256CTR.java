package org.ok.protocols.aes;

import org.ok.protocols.Block;

import java.nio.ByteBuffer;

public class AES256CTR {
    private AES256 aes;

    public AES256CTR() {
        aes = new AES256();
    }

    public Block encrypt(AESKey key, Block plaintext, Block nonce) {
        int blockSize = 16;
        int numBlocks = (plaintext.getSizeBytes() + blockSize - 1) / blockSize;

        Block[] blocks = new Block[numBlocks];
        for(int i = 0; i < numBlocks; i++) {
            byte[] counterBlockData = ByteBuffer.allocate(blockSize).put(nonce.getData()).putLong(i).array();
            Block counterBlock = new Block(blockSize, counterBlockData);

            Block keyStream = aes.encrypt(counterBlock, key);

            int start = i * blockSize;
            int end = Math.min(start + blockSize, plaintext.getSizeBytes());
            blocks[i] = plaintext.subData(start, end).xor(keyStream);
        }

        return Block.concat(blocks);
    }

    public Block decrypt(AESKey key, Block block, Block nonce) {
        return encrypt(key, block, nonce);
    }
}
