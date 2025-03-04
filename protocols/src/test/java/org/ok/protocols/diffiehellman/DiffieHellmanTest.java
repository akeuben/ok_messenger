package org.ok.protocols.diffiehellman;

import org.junit.jupiter.api.Test;
import org.ok.protocols.Block;

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class DiffieHellmanTest {
    @Test
    public void testMakeSharedSecret() throws InvalidKeySpecException, InvalidKeyException {
        DHKeyPair aliceKeys = new DHKeyPair();
        DHKeyPair bobKeys = new DHKeyPair();

        Block bobSecret = DiffieHellman.EstablishSharedSecret(bobKeys, aliceKeys.publicKey);
        Block aliceSecret = DiffieHellman.EstablishSharedSecret(aliceKeys, bobKeys.publicKey);

        assertEquals(bobSecret, aliceSecret);
    }
}
