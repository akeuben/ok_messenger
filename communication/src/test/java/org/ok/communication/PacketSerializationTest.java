package org.ok.communication;

import org.junit.jupiter.api.Test;
import org.ok.communication.packets.*;
import org.ok.protocols.Block;
import org.ok.protocols.diffiehellman.DiffieHellman;
import org.ok.protocols.doubleratchet.DoubleRatchet;
import org.ok.protocols.doubleratchet.DoubleRatchetMessage;
import org.ok.protocols.x3dh.PrekeyBundle;
import org.ok.protocols.x3dh.X3DH;
import org.ok.protocols.x3dh.X3DHMessage;
import org.ok.protocols.x3dh.X3DHResult;
import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.curve25519.Curve25519KeyPair;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class PacketSerializationTest {

    private static final Curve25519 curve = Curve25519.getInstance(Curve25519.BEST);

    private static class TestPacket extends Packet {

        private final String message;

        public TestPacket(String message) {
            super((byte) 0x01, (byte) 0x01);
            this.message = message;
        }

        public TestPacket(byte[] serializedData) {
            super((byte) 0x01, (byte) 0x01);
            this.message = new String(serializedData, StandardCharsets.UTF_8);
        }

        @Override
        protected byte[] serializeData() {
            return message.getBytes(StandardCharsets.UTF_8);
        }
    }

    private static <T extends Packet> T encodeDecode(T packet) {
        byte[] encoded = packet.serialize();
        //noinspection unchecked
        return (T) PacketManager.deserialize(encoded);
    }

    @Test
    public void TestTestPacket() {
        PacketManager.register((byte) 0x01, TestPacket.class);

        TestPacket packet = new TestPacket("Hello, World!");

        byte[] encoded = packet.serialize();

        TestPacket decoded = (TestPacket) PacketManager.deserialize(encoded);

        assertEquals(packet.message, decoded.message);
    }

    @Test
    public void TestInboundLoginPacket() {
        PacketManager.register((byte) 0x02, InboundLoginPacket.class);

        InboundLoginPacket packet = new InboundLoginPacket("avery", "avery_password");

        InboundLoginPacket decoded = encodeDecode(packet);

        assertEquals(packet.username, decoded.username);
        assertEquals(packet.password, decoded.password);
    }

    @Test
    public void TestOutboundInitialMessagePacket() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PacketManager.register((byte) 0x03, OutboundInitialMessagePacket.class);

        Curve25519KeyPair aliceKeys = curve.generateKeyPair();
        Curve25519KeyPair bobKeys = curve.generateKeyPair();

        Curve25519KeyPair bobSignedPrekey = curve.generateKeyPair();
        Curve25519KeyPair bobOneTimePrekey = curve.generateKeyPair();

        PrekeyBundle bobPrekeyBundle = X3DH.createPrekeyBundle(bobKeys, bobSignedPrekey, bobOneTimePrekey);

        X3DHResult aliceResult = X3DH.runSend(bobPrekeyBundle, aliceKeys);

        KeyPair bobKeyPair = DiffieHellman.GenerateKeyPair();

        DoubleRatchet alice = new DoubleRatchet(aliceResult.getSK(), bobKeyPair.getPublic());

        DoubleRatchetMessage encyrpted = alice.encrypt(new Block("Hello, World!"), aliceResult.getAD());

        X3DHMessage message = new X3DHMessage(new Block(aliceKeys.getPublicKey()), aliceResult.getEphemeralKey(), 0, encyrpted);

        OutboundInitialMessagePacket packet = new OutboundInitialMessagePacket(message);

        OutboundInitialMessagePacket decoded = encodeDecode(packet);

        assertEquals(packet.identityKey, decoded.identityKey);
        assertEquals(packet.emphemeralKey, decoded.emphemeralKey);
        assertEquals(packet.prekeyID, decoded.prekeyID);
        assertEquals(packet.data, decoded.data);
        assertEquals(packet.pubKey, decoded.pubKey);
        assertEquals(packet.pn, decoded.pn);
        assertEquals(packet.n, decoded.n);
    }

    @Test
    public void TestInboundInitialMessagePacket() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PacketManager.register((byte) 0x13, InboundInitialMessagePacket.class);

        Curve25519KeyPair aliceKeys = curve.generateKeyPair();
        Curve25519KeyPair bobKeys = curve.generateKeyPair();

        Curve25519KeyPair bobSignedPrekey = curve.generateKeyPair();
        Curve25519KeyPair bobOneTimePrekey = curve.generateKeyPair();

        PrekeyBundle bobPrekeyBundle = X3DH.createPrekeyBundle(bobKeys, bobSignedPrekey, bobOneTimePrekey);

        X3DHResult aliceResult = X3DH.runSend(bobPrekeyBundle, aliceKeys);

        KeyPair bobKeyPair = DiffieHellman.GenerateKeyPair();

        DoubleRatchet alice = new DoubleRatchet(aliceResult.getSK(), bobKeyPair.getPublic());

        DoubleRatchetMessage encyrpted = alice.encrypt(new Block("Hello, World!"), aliceResult.getAD());

        X3DHMessage message = new X3DHMessage(new Block(aliceKeys.getPublicKey()), aliceResult.getEphemeralKey(), 0, encyrpted);

        InboundInitialMessagePacket packet = new InboundInitialMessagePacket("avery", message);

        InboundInitialMessagePacket decoded = encodeDecode(packet);

        assertEquals(packet.destination, decoded.destination);
        assertEquals(packet.identityKey, decoded.identityKey);
        assertEquals(packet.emphemeralKey, decoded.emphemeralKey);
        assertEquals(packet.prekeyID, decoded.prekeyID);
        assertEquals(packet.data, decoded.data);
        assertEquals(packet.pubKey, decoded.pubKey);
        assertEquals(packet.pn, decoded.pn);
        assertEquals(packet.n, decoded.n);
    }

    @Test
    public void TestOutboundMessagePacket() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PacketManager.register((byte) 0x04, OutboundMessagePacket.class);

        Block SK = Block.fromHexString("c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558");
        KeyPair bobKeyPair = DiffieHellman.GenerateKeyPair();

        DoubleRatchet alice = new DoubleRatchet(SK, bobKeyPair.getPublic());

        Block AD = Block.fromHexString("44116f1a6af9c79c123B8A12");

        DoubleRatchetMessage message = alice.encrypt(new Block("Hello, World!"), AD);

        OutboundMessagePacket packet = new OutboundMessagePacket(message);

        OutboundMessagePacket decoded = encodeDecode(packet);

        assertEquals(packet.data, decoded.data);
        assertEquals(packet.pubKey, decoded.pubKey);
        assertEquals(packet.pn, decoded.pn);
        assertEquals(packet.n, decoded.n);
    }

    @Test
    public void TestInboundMessagePacket() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PacketManager.register((byte) 0x14, InboundMessagePacket.class);

        Block SK = Block.fromHexString("c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558");
        KeyPair bobKeyPair = DiffieHellman.GenerateKeyPair();

        DoubleRatchet alice = new DoubleRatchet(SK, bobKeyPair.getPublic());

        Block AD = Block.fromHexString("44116f1a6af9c79c123B8A12");

        DoubleRatchetMessage message = alice.encrypt(new Block("Hello, World!"), AD);

        InboundMessagePacket packet = new InboundMessagePacket("avery", message);

        InboundMessagePacket decoded = encodeDecode(packet);

        assertEquals(packet.destination, decoded.destination);
        assertEquals(packet.data, decoded.data);
        assertEquals(packet.pubKey, decoded.pubKey);
        assertEquals(packet.pn, decoded.pn);
        assertEquals(packet.n, decoded.n);
    }

    @Test
    public void TestOutboundLoginResponsePacket() {
        PacketManager.register((byte) 0x12, OutboundLoginResponsePacket.class);
        OutboundLoginResponsePacket packet = new OutboundLoginResponsePacket(OutboundLoginResponsePacket.LoginResponseValue.INVALID_PASSWORD);
        OutboundLoginResponsePacket decoded = encodeDecode(packet);

        assertEquals(packet.response, decoded.response);

        packet = new OutboundLoginResponsePacket(OutboundLoginResponsePacket.LoginResponseValue.INVALID_USER);
        decoded = encodeDecode(packet);

        assertEquals(packet.response, decoded.response);

        packet = new OutboundLoginResponsePacket(OutboundLoginResponsePacket.LoginResponseValue.SUCCESS);
        decoded = encodeDecode(packet);

        assertEquals(packet.response, decoded.response);
    }

}
