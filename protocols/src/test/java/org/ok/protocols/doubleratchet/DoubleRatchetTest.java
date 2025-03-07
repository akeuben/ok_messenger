package org.ok.protocols.doubleratchet;


import org.junit.jupiter.api.Test;
import org.ok.protocols.Block;
import org.ok.protocols.diffiehellman.DiffieHellman;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

public class DoubleRatchetTest {

    @Test
    public void TestDoubleRatchet() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        Block SK = Block.fromHexString("c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558");
        KeyPair bobKeyPair = DiffieHellman.GenerateKeyPair();

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

}
