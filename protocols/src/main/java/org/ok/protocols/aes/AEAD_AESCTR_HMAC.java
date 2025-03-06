package org.ok.protocols.aes;

import org.ok.protocols.Block;
import org.ok.protocols.HMAC;
import org.ok.protocols.KDF;

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

        byte[][] res = new KDF().kdf_ck(messageKey);

        Block nonceBlock = new Block(nonce);

        Block ciphertext = aes.encrypt(new AESKey(res[0]), plaintext, associatedData);

        Block hmac = new HMAC().encode(Block.concat(nonceBlock, ciphertext, associatedData), new Block(res[1]));

        return Block.concat(nonceBlock, ciphertext, hmac);
    }

    public Block decrypt(byte[] messageKey, Block encryptedData, Block associatedData) {
        if(encryptedData.getSizeBytes() < 48) throw new RuntimeException("Invalid ciphertext length!");

        byte[][] res = new KDF().kdf_ck(messageKey);

        Block nonce = encryptedData.subData(0, 16);
        Block ciphertext = encryptedData.subData(16, encryptedData.getSizeBytes() - 32);
        Block recievedHmac = encryptedData.subData(encryptedData.getSizeBytes() - 32, encryptedData.getSizeBytes());

        Block expectedHmac = new HMAC().encode(Block.concat(nonce, ciphertext, associatedData), new Block(res[1]));
        if(!recievedHmac.equals(expectedHmac)) {
            throw new RuntimeException("Failed to verify message through HMAC");
        }

        return aes.decrypt(new AESKey(res[0]), ciphertext, nonce);
    }
}
