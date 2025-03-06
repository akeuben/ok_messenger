package org.ok.protocols.aes;

import org.ok.protocols.Block;

public class AES256CBC {
    private AES256 aes;

    public AES256CBC() {
        aes = new AES256();
    }

    public Block encrypt(Block plaintext_unpadded, Block iv, AESKey key) {
        int blockSize = 16;
        Block plaintext = plaintext_unpadded.pkcs7Pad(16);
        int numBlocks = plaintext.getSizeBytes() / blockSize;

        Block[] blocks = new Block[numBlocks + 1];
        blocks[0] = iv;

        for(int i = 1; i <= numBlocks; i++) {
            int start = (i - 1) * blockSize;
            int end = start + blockSize;
            blocks[i] = aes.encrypt(plaintext.subData(start, end).xor(blocks[i-1]), key);
        }

        return Block.concat(blocks);
    }

    public Block decrypt(Block ciphertext, AESKey key) {
        int blockSize = 16;
        int numBlocks = ciphertext.getSizeBytes()/blockSize - 1;

        Block[] decrypted = new Block[numBlocks];
        for(int i = 0; i < numBlocks; i++) {
            Block thisBlock = ciphertext.subData((i + 1) * blockSize, (i + 2) * blockSize);
            Block prevBlock = ciphertext.subData(i * blockSize, (i + 1) * blockSize);
            decrypted[i] = aes.decrypt(thisBlock, key).xor(prevBlock);
        }

        return Block.concat(decrypted).pkcs7Unpad(blockSize);
    }
}
