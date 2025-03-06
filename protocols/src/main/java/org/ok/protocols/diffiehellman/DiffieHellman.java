package org.ok.protocols.diffiehellman;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.NamedParameterSpec;

public class DiffieHellman {
    public static KeyPair GenerateKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XDH");
        NamedParameterSpec spec = new NamedParameterSpec("X25519");
        kpg.initialize(spec);
        return kpg.generateKeyPair();
    }

    public static byte[] Run(KeyPair kp, PublicKey pubKey) {
        try {
            KeyAgreement ka = KeyAgreement.getInstance("XDH");
            ka.init(kp.getPrivate());
            ka.doPhase(pubKey, true);
            return ka.generateSecret();
        } catch (Exception e) {
            throw new RuntimeException("uh oh");
        }
    }
}
