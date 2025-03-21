package org.ok.protocols.diffiehellman;

import java.io.Serializable;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;

public class DHKeyPair implements Serializable {
    private static KeyPairGenerator kpg;
    private static final NamedParameterSpec paramSpec = new NamedParameterSpec("X25519");

    static {
        try {
            kpg = KeyPairGenerator.getInstance("XDH");
            kpg.initialize(paramSpec);
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            System.exit(1);
        }
    }

    PublicKey publicKey;
    PrivateKey privateKey;

    public DHKeyPair() throws InvalidKeySpecException {
        KeyPair kp = kpg.generateKeyPair();

        publicKey = kp.getPublic();
        privateKey = kp.getPrivate();
    }
}
