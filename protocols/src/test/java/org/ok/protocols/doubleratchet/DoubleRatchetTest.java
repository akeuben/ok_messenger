package org.ok.protocols.doubleratchet;


import org.junit.jupiter.api.Test;
import org.ok.protocols.Block;
import org.ok.protocols.diffiehellman.DiffieHellman;
import org.ok.protocols.x3dh.*;
import org.whispersystems.curve25519.Curve25519;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

public class DoubleRatchetTest {

    private static Curve25519 curve = Curve25519.getInstance(Curve25519.BEST);

    @Test
    public void TestDoubleRatchet() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        Block SK = Block.fromHexString("c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558");
        KeyPair bobKeyPair = DiffieHellman.GenerateKeyPair();

        System.out.println("Bob Key Pair" + new Block(bobKeyPair.getPublic()));

        DoubleRatchet bob = new DoubleRatchet(SK, bobKeyPair);
        DoubleRatchet alice = new DoubleRatchet(SK, bobKeyPair.getPublic());

        Block AD = Block.fromHexString("44116f1a6af9c79c123B8A12");

        DoubleRatchetMessage encyrpted = alice.encrypt(new Block("Hello, World!"), AD);
        Block decrypted = bob.decrypt(encyrpted, AD);

        assertEquals(new Block("Hello, World!"), decrypted);

        DoubleRatchetMessage msg = bob.encrypt(new Block("Hello, Alice"), AD);
        Block plzWork = alice.decrypt(msg, AD);

        assertEquals(new Block("Hello, Alice"), plzWork);
    }

    @Test
    public void TestDoubleRatchet2() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        X3DHKeyPair aliceKeys = X3DHKeyPair.from("f4c834f914db1bcf1199ddcf757774f2fd72e74712c29f21864e8a4486dcac3b", "a80b437250cd22b14b2cedaa5682eafe7ba11aba83769b8b18a51210bf922e42");
        X3DHKeyPair bobKeys = X3DHKeyPair.from("24120b1932d3781b4a420ef9926e32dd2c27fa1c121d49f8a53c854ea5effb53", "d09886f78e387053aa4f336b712f64b231821bbb64ecbbafe70b0bf5c577334f");

        System.out.println("X3DH Alice: " + "Pub: " + new Block(aliceKeys.getPublicKey()) + ", Priv: " + new Block(aliceKeys.getPrivateKey()));
        System.out.println("X3DH Bob: " + "Pub: " + new Block(bobKeys.getPublicKey()) + ", Priv: " + new Block(bobKeys.getPrivateKey()));

        X3DHKeyPair bobSignedPrekey = X3DHKeyPair.from("3930deac493e4f06a0e0779124aab1a3e704a115215212cf6c3b52e7a926b953", "b060c24f2a6cb3df00bec195ad0b34396535def7868b1e5bb8a7533b05a1437e");

        System.out.println("Prekey Bob: " + "Pub: " + new Block(bobSignedPrekey.getPublicKey()) + ", Priv: " + new Block(bobSignedPrekey.getPrivateKey()));

        PrekeyBundle bobPrekeyBundle = X3DH.createPrekeyBundle(bobKeys, bobSignedPrekey);

        KeyPair bobKeyPair = DiffieHellman.from("302a300506032b656e0321001fa22ca7700b28e9a7452a9731b566603fc98e239e21f0eb6a65b92f0d95b03b", "302e020100300506032b656e04220420450fa848debe0ffcacb8d8d066bc543f773e1e52fd54a8ef4276df70964f039d");

        System.out.println("Bob Key Pair: Pub: " + new Block(bobKeyPair.getPublic()) + ", Priv: " +  new Block(bobKeyPair.getPrivate()));

        X3DHResult resultSend = X3DH.runSend(bobPrekeyBundle, aliceKeys);

        DoubleRatchet alice = new DoubleRatchet(resultSend.getSK(), bobKeyPair.getPublic());

        System.out.println("SK: " + resultSend.getSK());
        System.out.println("AD: " + resultSend.getAD());

        DoubleRatchetMessage encyrpted = alice.encrypt(new Block("Hello, World!"), resultSend.getAD());

        X3DHResult resultRec = X3DH.runReceive(bobKeys, bobSignedPrekey, null, new X3DHMessage(
                new Block(aliceKeys.getPublicKey()),
                resultSend.getEphemeralKey(),
                0,
                encyrpted
        ));

        DoubleRatchet bob = new DoubleRatchet(resultRec.getSK(), bobKeyPair);

        Block decrypted = bob.decrypt(encyrpted, resultRec.getAD());

        assertEquals(new Block("Hello, World!"), decrypted);

        DoubleRatchetMessage msg = alice.encrypt(new Block("Hello, Alice"), resultSend.getAD());
        Block plzWork = bob.decrypt(msg, resultRec.getAD());

        assertEquals(new Block("Hello, Alice"), plzWork);
    }

}
