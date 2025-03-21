package org.ok.communication;

import org.junit.jupiter.api.Test;
import org.ok.communication.packets.*;
import org.ok.protocols.Block;
import org.ok.protocols.diffiehellman.DiffieHellman;
import org.ok.protocols.doubleratchet.DoubleRatchet;
import org.ok.protocols.doubleratchet.DoubleRatchetMessage;
import org.ok.protocols.x3dh.*;
import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.curve25519.Curve25519KeyPair;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.*;

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
        return (T) PacketManager.getInstance().deserialize(encoded);
    }

    @Test
    public void TestTestPacket() {
        PacketManager.getInstance().register((byte) 0x01, TestPacket.class);

        TestPacket packet = new TestPacket("Hello, World!");

        byte[] encoded = packet.serialize();

        TestPacket decoded = (TestPacket) PacketManager.getInstance().deserialize(encoded);

        assertEquals(packet.message, decoded.message);
    }

    @Test
    public void TestInboundLoginPacket() {
        PacketManager.getInstance().register((byte) 0x02, InboundLoginPacket.class);

        InboundLoginPacket packet = new InboundLoginPacket("avery", "avery_password");

        InboundLoginPacket decoded = encodeDecode(packet);

        assertEquals(packet.username, decoded.username);
        assertEquals(packet.password, decoded.password);
    }

    @Test
    public void TestOutboundInitialMessagePacket() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PacketManager.getInstance().register((byte) 0x03, OutboundInitialMessagePacket.class);

        X3DHKeyPair aliceKeys = new X3DHKeyPair(curve.generateKeyPair());
        X3DHKeyPair bobKeys = new X3DHKeyPair(curve.generateKeyPair());

        X3DHKeyPair bobSignedPrekey = new X3DHKeyPair(curve.generateKeyPair());
        X3DHKeyPair bobOneTimePrekey = new X3DHKeyPair(curve.generateKeyPair());

        PrekeyBundle bobPrekeyBundle = X3DH.createPrekeyBundle(bobKeys, bobSignedPrekey, bobOneTimePrekey);

        X3DHResult aliceResult = X3DH.runSend(bobPrekeyBundle, aliceKeys);

        KeyPair bobKeyPair = DiffieHellman.GenerateKeyPair();

        DoubleRatchet alice = new DoubleRatchet(aliceResult.getSK(), bobKeyPair.getPublic());

        DoubleRatchetMessage encyrpted = alice.encrypt(new Block("Hello, World!"), aliceResult.getAD());

        X3DHMessage message = new X3DHMessage(new Block(aliceKeys.getPublicKey()), aliceResult.getEphemeralKey(), 0, encyrpted);

        OutboundInitialMessagePacket packet = new OutboundInitialMessagePacket("avery", message);

        OutboundInitialMessagePacket decoded = encodeDecode(packet);

        assertEquals(packet.origin, decoded.origin);
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
        PacketManager.getInstance().register((byte) 0x13, InboundInitialMessagePacket.class);

        X3DHKeyPair aliceKeys = new X3DHKeyPair(curve.generateKeyPair());
        X3DHKeyPair bobKeys = new X3DHKeyPair(curve.generateKeyPair());

        X3DHKeyPair bobSignedPrekey = new X3DHKeyPair(curve.generateKeyPair());
        X3DHKeyPair bobOneTimePrekey = new X3DHKeyPair(curve.generateKeyPair());

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
        PacketManager.getInstance().register((byte) 0x04, OutboundMessagePacket.class);

        Block SK = Block.fromHexString("c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558");
        KeyPair bobKeyPair = DiffieHellman.GenerateKeyPair();

        DoubleRatchet alice = new DoubleRatchet(SK, bobKeyPair.getPublic());

        Block AD = Block.fromHexString("44116f1a6af9c79c123B8A12");

        DoubleRatchetMessage message = alice.encrypt(new Block("Hello, World!"), AD);

        OutboundMessagePacket packet = new OutboundMessagePacket("avery", message);

        OutboundMessagePacket decoded = encodeDecode(packet);

        assertEquals(packet.origin, decoded.origin);
        assertEquals(packet.data, decoded.data);
        assertEquals(packet.pubKey, decoded.pubKey);
        assertEquals(packet.pn, decoded.pn);
        assertEquals(packet.n, decoded.n);
    }

    @Test
    public void TestInboundMessagePacket() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PacketManager.getInstance().register((byte) 0x14, InboundMessagePacket.class);

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
        PacketManager.getInstance().register((byte) 0x12, OutboundLoginResponsePacket.class);
        OutboundLoginResponsePacket packet = new OutboundLoginResponsePacket(OutboundLoginResponsePacket.LoginResponseValue.INVALID_PASSWORD, "avery");
        OutboundLoginResponsePacket decoded = encodeDecode(packet);

        assertEquals(packet.response, decoded.response);
        assertEquals(packet.username, decoded.username);

        packet = new OutboundLoginResponsePacket(OutboundLoginResponsePacket.LoginResponseValue.INVALID_USER, "avery");
        decoded = encodeDecode(packet);

        assertEquals(packet.response, decoded.response);
        assertEquals(packet.username, decoded.username);

        packet = new OutboundLoginResponsePacket(OutboundLoginResponsePacket.LoginResponseValue.SUCCESS, "avery");
        decoded = encodeDecode(packet);

        assertEquals(packet.response, decoded.response);
        assertEquals(packet.username, decoded.username);
    }

    @Test
    public void TestInboundRequestPrekeyBundlePacket() {
        PacketManager.getInstance().register((byte) 0x16, InboundRequestPrekeyBundlePacket.class);

        String user1 = "testUser1";
        InboundRequestPrekeyBundlePacket packet1 = new InboundRequestPrekeyBundlePacket(user1);
        InboundRequestPrekeyBundlePacket decoded1 = encodeDecode(packet1);

        assertEquals(packet1.user, decoded1.user);

        String user2 = "anotherUserWithALongerName";
        InboundRequestPrekeyBundlePacket packet2 = new InboundRequestPrekeyBundlePacket(user2);
        InboundRequestPrekeyBundlePacket decoded2 = encodeDecode(packet2);

        assertEquals(packet2.user, decoded2.user);

        String user3 = "";
        InboundRequestPrekeyBundlePacket packet3 = new InboundRequestPrekeyBundlePacket(user3);
        InboundRequestPrekeyBundlePacket decoded3 = encodeDecode(packet3);

        assertEquals(packet3.user, decoded3.user);

        String user4 = "User with spaces";
        InboundRequestPrekeyBundlePacket packet4 = new InboundRequestPrekeyBundlePacket(user4);
        InboundRequestPrekeyBundlePacket decoded4 = encodeDecode(packet4);

        assertEquals(packet4.user, decoded4.user);
    }
    @Test
    public void TestInboundUpdatePrekeysPacket() {
        PacketManager.getInstance().register((byte) 0x15, InboundUpdatePrekeysPacket.class);

        Block[] bundles1 = {
                new Block(new byte[]{1, 2, 3}),
                new Block(new byte[]{4, 5, 6, 7}),
                new Block(new byte[]{8})
        };
        InboundUpdatePrekeysPacket packet1 = new InboundUpdatePrekeysPacket(bundles1);
        InboundUpdatePrekeysPacket decoded1 = encodeDecode(packet1);

        assertEquals(packet1.prekeyBundles.size(), decoded1.prekeyBundles.size());
        for (int i = 0; i < packet1.prekeyBundles.size(); i++) {
            assertArrayEquals(packet1.prekeyBundles.get(i).getData(), decoded1.prekeyBundles.get(i).getData());
        }

        Block[] bundles2 = {};
        InboundUpdatePrekeysPacket packet2 = new InboundUpdatePrekeysPacket(bundles2);
        InboundUpdatePrekeysPacket decoded2 = encodeDecode(packet2);

        assertEquals(packet2.prekeyBundles.size(), decoded2.prekeyBundles.size());

        Block[] bundles3 = {
                new Block(new byte[]{10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20})
        };
        InboundUpdatePrekeysPacket packet3 = new InboundUpdatePrekeysPacket(bundles3);
        InboundUpdatePrekeysPacket decoded3 = encodeDecode(packet3);

        assertEquals(packet3.prekeyBundles.size(), decoded3.prekeyBundles.size());
        for (int i = 0; i < packet3.prekeyBundles.size(); i++) {
            assertArrayEquals(packet3.prekeyBundles.get(i).getData(), decoded3.prekeyBundles.get(i).getData());
        }

        Block[] bundles4 = {
                new Block(new byte[]{}),
                new Block(new byte[]{1})
        };

        InboundUpdatePrekeysPacket packet4 = new InboundUpdatePrekeysPacket(bundles4);
        InboundUpdatePrekeysPacket decoded4 = encodeDecode(packet4);

        assertEquals(packet4.prekeyBundles.size(), decoded4.prekeyBundles.size());
        for (int i = 0; i < packet4.prekeyBundles.size(); i++){
            assertArrayEquals(packet4.prekeyBundles.get(i).getData(), decoded4.prekeyBundles.get(i).getData());
        }
    }
    @Test
    public void TestOutboundPrekeyBundlePacket() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PacketManager.getInstance().register((byte) 0x06, OutboundPrekeyBundlePacket.class);

        Block identityKey1 = new Block(new byte[]{1, 2, 3});
        Block signedPrekey1 = new Block(new byte[]{4, 5, 6});
        Block prekeySignature1 = new Block(new byte[]{7, 8, 9});
        Block oneTimePrekey1 = new Block(new byte[]{10, 11, 12});

        PublicKey key = DiffieHellman.GenerateKeyPair().getPublic();

        PrekeyBundle bundle1 = new PrekeyBundle(identityKey1, signedPrekey1, prekeySignature1, oneTimePrekey1);
        OutboundPrekeyBundlePacket packet1 = new OutboundPrekeyBundlePacket(bundle1, key);
        OutboundPrekeyBundlePacket decoded1 = encodeDecode(packet1);

        assertEquals(packet1.bundle.getIdentityKey().getData().length, decoded1.bundle.getIdentityKey().getData().length);
        assertArrayEquals(packet1.bundle.getIdentityKey().getData(), decoded1.bundle.getIdentityKey().getData());
        assertArrayEquals(packet1.bundle.getSignedPrekey().getData(), decoded1.bundle.getSignedPrekey().getData());
        assertArrayEquals(packet1.bundle.getPrekeySignature().getData(), decoded1.bundle.getPrekeySignature().getData());
        assertArrayEquals(packet1.bundle.getOneTimePrekey().getData(), decoded1.bundle.getOneTimePrekey().getData());

        Block identityKey2 = new Block(new byte[]{13, 14});
        Block signedPrekey2 = new Block(new byte[]{15});
        Block prekeySignature2 = new Block(new byte[]{16, 17, 18, 19});

        PrekeyBundle bundle2 = new PrekeyBundle(identityKey2, signedPrekey2, prekeySignature2);
        OutboundPrekeyBundlePacket packet2 = new OutboundPrekeyBundlePacket(bundle2, key);
        OutboundPrekeyBundlePacket decoded2 = encodeDecode(packet2);

        assertArrayEquals(packet2.bundle.getIdentityKey().getData(), decoded2.bundle.getIdentityKey().getData());
        assertArrayEquals(packet2.bundle.getSignedPrekey().getData(), decoded2.bundle.getSignedPrekey().getData());
        assertArrayEquals(packet2.bundle.getPrekeySignature().getData(), decoded2.bundle.getPrekeySignature().getData());
        assertNull(decoded2.bundle.getOneTimePrekey());

        Block identityKey3 = new Block(new byte[]{});
        Block signedPrekey3 = new Block(new byte[]{});
        Block prekeySignature3 = new Block(new byte[]{});
        Block onetimePrekey3 = new Block(new byte[]{});
        PrekeyBundle bundle3 = new PrekeyBundle(identityKey3, signedPrekey3, prekeySignature3,onetimePrekey3);
        OutboundPrekeyBundlePacket packet3 = new OutboundPrekeyBundlePacket(bundle3, key);
        OutboundPrekeyBundlePacket decoded3 = encodeDecode(packet3);
        assertArrayEquals(packet3.bundle.getIdentityKey().getData(), decoded3.bundle.getIdentityKey().getData());
        assertArrayEquals(packet3.bundle.getSignedPrekey().getData(), decoded3.bundle.getSignedPrekey().getData());
        assertArrayEquals(packet3.bundle.getPrekeySignature().getData(), decoded3.bundle.getPrekeySignature().getData());
        assertArrayEquals(packet3.bundle.getOneTimePrekey().getData(), decoded3.bundle.getOneTimePrekey().getData());
    }

    @Test
    public void TestOutboundRequestPrekeysPacket() {
        PacketManager.getInstance().register((byte) 0x05, OutboundRequestPrekeysPacket.class);

        OutboundRequestPrekeysPacket packet1 = new OutboundRequestPrekeysPacket();
        OutboundRequestPrekeysPacket decoded1 = encodeDecode(packet1);

        assertArrayEquals(packet1.serialize(), decoded1.serialize());

        // Test with a byte array constructor
        byte[] someBytes = {1, 2, 3};
        OutboundRequestPrekeysPacket packet2 = new OutboundRequestPrekeysPacket(someBytes);
        OutboundRequestPrekeysPacket decoded2 = encodeDecode(packet2);

        assertArrayEquals(packet2.serialize(), decoded2.serialize());

        //Ensure that the serialize data returns an empty byte array.
        assertEquals(2, packet1.serialize().length);
        assertEquals(2, packet2.serialize().length);

    }

    @Test
    public void TestInboundRegisterPacket() {
        PacketManager.getInstance().register((byte) 0x17, InboundRegisterPacket.class);

        String username1 = "testUser";
        String password1 = "testPassword";
        InboundRegisterPacket packet1 = new InboundRegisterPacket(username1, password1);
        InboundRegisterPacket decoded1 = encodeDecode(packet1);

        assertEquals(packet1.username, decoded1.username);
        assertEquals(packet1.password, decoded1.password);

        String username2 = "anotherUser";
        String password2 = "anotherLongPassword";
        InboundRegisterPacket packet2 = new InboundRegisterPacket(username2, password2);
        InboundRegisterPacket decoded2 = encodeDecode(packet2);

        assertEquals(packet2.username, decoded2.username);
        assertEquals(packet2.password, decoded2.password);

        String username3 = "";
        String password3 = "";
        InboundRegisterPacket packet3 = new InboundRegisterPacket(username3, password3);
        InboundRegisterPacket decoded3 = encodeDecode(packet3);

        assertEquals(packet3.username, decoded3.username);
        assertEquals(packet3.password, decoded3.password);
    }

    @Test
    public void TestOutboundRegisterResponsePacket() {
        PacketManager.getInstance().register((byte) 0x18, OutboundRegisterResponsePacket.class);

        OutboundRegisterResponsePacket packet1 = new OutboundRegisterResponsePacket(true);
        OutboundRegisterResponsePacket decoded1 = encodeDecode(packet1);

        assertEquals(packet1.success, decoded1.success);

        OutboundRegisterResponsePacket packet2 = new OutboundRegisterResponsePacket(false);
        OutboundRegisterResponsePacket decoded2 = encodeDecode(packet2);

        assertEquals(packet2.success, decoded2.success);
    }
}
