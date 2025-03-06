package org.ok.protocols.aes;

import org.ok.protocols.Block;
import org.ok.protocols.kdf.HKDF;
import org.ok.protocols.hmacsha256.HMAC;

public class AEAD {
    private AES256CBC aes;
    private HKDF hkdf;
    private HMAC hmac;

    public AEAD() {
        aes = new AES256CBC();
        hkdf = new HKDF();
        hmac = new HMAC();
    }

    public Block encrypt(Block data, AESKey key, Block associated_data) {
        Block hkdfMaterial = hkdf.hkdf(new Block(new byte[256/8]), key, new Block(new byte[] {0x73}), 80);
        AESKey encKey = new AESKey(hkdfMaterial.subData(0, 32).getData());
        Block authKey = hkdfMaterial.subData(32, 64);
        Block iv = hkdfMaterial.subData(64, 80);

        Block encryptedData = aes.encrypt(data, iv, encKey);
        Block authentectedData = hmac.encode(Block.concat(associated_data, encryptedData), authKey);

        return Block.concat(authentectedData, encryptedData);
    }

    public Block decrypt(Block data, AESKey key, Block associated_data) {
        Block hkdfMaterial = hkdf.hkdf(new Block(new byte[256/8]), key, new Block(new byte[] {0x73}), 80);
        AESKey encKey = new AESKey(hkdfMaterial.subData(0, 32).getData());
        Block authKey = hkdfMaterial.subData(32, 64);
        Block iv = hkdfMaterial.subData(64, 80);

        Block actualHMAC = data.subData(0, 32);
        Block encryptedData = data.subData(32, data.getSizeBytes());

        Block plaintext = aes.decrypt(encryptedData, encKey);
        Block expectedHMAC = hmac.encode(Block.concat(associated_data, encryptedData), authKey);

        if(!actualHMAC.equals(expectedHMAC)) {
            throw new RuntimeException("tampered message");
        }

        return plaintext;
    }
}
