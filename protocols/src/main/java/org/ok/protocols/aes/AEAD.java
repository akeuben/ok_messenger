package org.ok.protocols.aes;

import org.ok.protocols.Block;
import org.ok.protocols.kdf.HKDF;
import org.ok.protocols.hmacsha256.HMAC;

import java.io.Serializable;

public class AEAD {

    public static Block encrypt(Block data, AESKey key, Block associated_data) {
        Block hkdfMaterial = HKDF.hkdf(new Block(new byte[256/8]), key, new Block(new byte[] {0x73}), 80);
        AESKey encKey = new AESKey(hkdfMaterial.subData(0, 32).getData());
        Block authKey = hkdfMaterial.subData(32, 64);
        Block iv = hkdfMaterial.subData(64, 80);

        Block encryptedData = AES256CBC.encrypt(data, iv, encKey);
        Block authentectedData = HMAC.encode(Block.concat(associated_data, encryptedData), authKey);

        return Block.concat(authentectedData, encryptedData);
    }

    public static Block decrypt(Block data, AESKey key, Block associated_data) {
        Block hkdfMaterial = HKDF.hkdf(new Block(new byte[256/8]), key, new Block(new byte[] {0x73}), 80);
        AESKey encKey = new AESKey(hkdfMaterial.subData(0, 32).getData());
        Block authKey = hkdfMaterial.subData(32, 64);
        Block iv = hkdfMaterial.subData(64, 80);

        Block actualHMAC = data.subData(0, 32);
        Block encryptedData = data.subData(32, data.getSizeBytes());

        Block plaintext = AES256CBC.decrypt(encryptedData, encKey);
        Block expectedHMAC = HMAC.encode(Block.concat(associated_data, encryptedData), authKey);

        if(!actualHMAC.equals(expectedHMAC)) {
            throw new RuntimeException("tampered message");
        }

        return plaintext;
    }
}
