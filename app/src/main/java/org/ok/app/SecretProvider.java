package org.ok.app;

import org.ok.protocols.x3dh.X3DHKeyPair;
import org.whispersystems.curve25519.Curve25519KeyPair;

import java.security.KeyPair;

public interface SecretProvider {
    KeyPair getDHKeyPair();
    X3DHKeyPair x3DHKeyPair();
    X3DHKeyPair signedPrekey();
}
