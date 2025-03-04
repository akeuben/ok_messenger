package org.ok.protocols.diffiehellman;

import org.ok.protocols.Block;

import javax.crypto.KeyAgreement;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

public class DiffieHellman {

    private static final KeyAgreement ka;

    static {
        try {
            ka = KeyAgreement.getInstance("XDH");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static Block EstablishSharedSecret(DHKeyPair dh_pair, PublicKey dh_pub) throws InvalidKeyException {
        ka.init(dh_pair.privateKey);
        ka.doPhase(dh_pub, true);
        byte[] secret = ka.generateSecret();

        return new Block(secret.length, secret);
    }
}
