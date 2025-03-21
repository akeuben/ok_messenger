package org.ok.app;

import org.ok.protocols.x3dh.X3DHKeyPair;
import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.curve25519.Curve25519KeyPair;

import java.security.KeyPair;

public class SecretManager implements SecretProvider{
    private static SecretManager instance;

    private final SecretProvider provider;

    public static void init(SecretProvider provider) {
        instance = new SecretManager(provider);
    }

    public static SecretManager getInstance() {
        return instance;
    }

    private SecretManager(SecretProvider provider) {
        this.provider = provider;
    }

    @Override
    public KeyPair getDHKeyPair() {
        return provider.getDHKeyPair();
    }

    @Override
    public X3DHKeyPair x3DHKeyPair() {
        return provider.x3DHKeyPair();
    }

    @Override
    public X3DHKeyPair signedPrekey() {
        return provider.signedPrekey();
    }
}
