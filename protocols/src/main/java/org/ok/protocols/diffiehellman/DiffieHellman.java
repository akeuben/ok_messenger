package org.ok.protocols.diffiehellman;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.NamedParameterSpec;

public class DiffieHellman {
    public static KeyPair GenerateKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XDH");
        NamedParameterSpec spec = new NamedParameterSpec("X25519");
        kpg.initialize(spec);
        return kpg.generateKeyPair();
    }
}
