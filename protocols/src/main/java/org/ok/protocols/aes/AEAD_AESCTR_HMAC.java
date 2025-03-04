package org.ok.protocols.aes;

import org.ok.protocols.Block;

import java.security.SecureRandom;

public class AEAD_AESCTR_HMAC {
    private AES256CTR aes;
    private SecureRandom random;

    public AEAD_AESCTR_HMAC() {
        aes = new AES256CTR();
        random = new SecureRandom();
    }

    public Block encrypt(byte[] messageKey, Block plaintext, Block associatedData) {
        byte[] nonce = new byte[8];
        random.nextBytes(nonce);

        Block nonceBlock = new Block(nonce);

        Block ciphertext = aes.encrypt(new AESKey(messageKey), plaintext, associatedData);

        Block hmac = HMACSHA256.hmac(hmacKey, Block.concat(nonceBlock, ciphertext, associatedData));

        return Block.concat(nonceBlock, ciphertext, hmac);
    }

    public Block decrypt(byte[] messageKey, Block encryptedData, Block associatedData) {
        if(encryptedData.getSizeBytes() < 48) throw new RuntimeException("Invalid ciphertext length!");

        Block nonce = encryptedData.subData(0, 16);
        Block ciphertext = encryptedData.subData(16, encryptedData.getSizeBytes() - 32);
        Block recievedHmac = encryptedData.subData(encryptedData.getSizeBytes() - 32, encryptedData.getSizeBytes());

        Block expectedHmac = HMACSHA256.hmac(hmacKey, Block.concat(nonce, ciphertext, associatedData));
        if(recievedHmac != expectedHmac) {
            throw new RuntimeException("Failed to verify message through HMAC");
        }

        return aes.decrypt(new AESKey(messageKey), ciphertext, nonce);
    }
}
