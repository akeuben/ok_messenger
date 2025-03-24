package org.ok.app;

import org.h2.mvstore.MVMap;
import org.ok.protocols.Block;
import org.ok.protocols.diffiehellman.DiffieHellman;
import org.ok.protocols.x3dh.X3DHKeyPair;
import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.curve25519.Curve25519KeyPair;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

public class InMemorySecretProvider implements SecretProvider {
    private static final Curve25519 curve = Curve25519.getInstance(Curve25519.BEST);

    private static final Map<String,KeyPair> dhKeyPairs = new HashMap<>();
    private static final Map<String, X3DHKeyPair> x3dhKeyPairs = new HashMap<>();
    private static final Map<String, X3DHKeyPair> signedPrekey = new HashMap<>();

    private final String username;

    public InMemorySecretProvider(String username) {
        this.username = username;
        if(!dhKeyPairs.containsKey(username)) {
            try {
                dhKeyPairs.put(username, DiffieHellman.GenerateKeyPair());
            } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
                throw new RuntimeException(e);
            }
        }

        if(!x3dhKeyPairs.containsKey(username)) {
            Curve25519KeyPair kp = curve.generateKeyPair();
            x3dhKeyPairs.put(username, new X3DHKeyPair(kp));
        }

        if(!signedPrekey.containsKey(username)) {
            Curve25519KeyPair kp = curve.generateKeyPair();
            signedPrekey.put(username, new X3DHKeyPair(kp));
        }

    }


    @Override
    public KeyPair getDHKeyPair() {
        return dhKeyPairs.get(username);
    }

    @Override
    public X3DHKeyPair x3DHKeyPair() {
        return x3dhKeyPairs.get(username);
    }

    @Override
    public X3DHKeyPair signedPrekey() {
        return signedPrekey.get(username);
    }
}
