package org.ok.protocols.x3dh;

import org.ok.protocols.Block;
import org.whispersystems.curve25519.Curve25519KeyPair;

import java.io.Serializable;

public class X3DHKeyPair implements Serializable {
    private final byte[] privateKey;
    private final byte[] publicKey;

    public X3DHKeyPair(Curve25519KeyPair kp) {
        privateKey = kp.getPrivateKey();
        publicKey = kp.getPublicKey();
    }

    public X3DHKeyPair(byte[] pk, byte[] sk) {
        this.publicKey = pk;
        this.privateKey = sk;
    }

    public byte[] getPrivateKey() {
        return privateKey;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public static X3DHKeyPair from(String pk, String sk) {
        byte[] pk1 = Block.fromHexString(pk).getData();
        byte[] sk1 = Block.fromHexString(sk).getData();

        return new X3DHKeyPair(pk1, sk1);
    }
}
