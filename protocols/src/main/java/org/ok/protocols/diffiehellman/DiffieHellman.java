package org.ok.protocols.diffiehellman;

import org.ok.protocols.Block;
import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.curve25519.Curve25519KeyPair;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.*;

public class DiffieHellman {
    public static KeyPair GenerateKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XDH");
        SecureRandom random = new SecureRandom();
        NamedParameterSpec spec = new NamedParameterSpec("X25519");
        kpg.initialize(spec, random);
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

    public static PublicKey decodePublicKey(byte[] encoded) {
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("XDH");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        try {
            return keyFactory.generatePublic(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public static KeyPair from(String pub, String pri) {
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("XDH");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        X509EncodedKeySpec pkeySpec = new X509EncodedKeySpec(Block.fromHexString(pub).getData());
        PKCS8EncodedKeySpec skeySpec = new PKCS8EncodedKeySpec(Block.fromHexString(pri).getData());
        try {
            PublicKey pubKey = keyFactory.generatePublic(pkeySpec);
            PrivateKey privKey = keyFactory.generatePrivate(skeySpec);

            return new KeyPair(pubKey, privKey);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] Run(byte[] privateKey, byte[] publicKey) {
        return Curve25519.getInstance(Curve25519.BEST).calculateAgreement(publicKey, privateKey);
    }
}
