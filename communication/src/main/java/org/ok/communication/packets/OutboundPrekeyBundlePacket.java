package org.ok.communication.packets;

import org.ok.communication.Packet;
import org.ok.protocols.Block;
import org.ok.protocols.diffiehellman.DiffieHellman;
import org.ok.protocols.x3dh.PrekeyBundle;

import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.PublicKey;

public class OutboundPrekeyBundlePacket extends Packet {
    public PrekeyBundle bundle;
    public PublicKey key;

    public OutboundPrekeyBundlePacket() {
        super((byte)0x01, (byte) 0x06);
    }

    public OutboundPrekeyBundlePacket(PrekeyBundle bundle, PublicKey key) {
        this();
        this.bundle = bundle;
        this.key = key;
    }

    public OutboundPrekeyBundlePacket(byte[] data) {
        this();
        ByteBuffer buffer = ByteBuffer.wrap(data);

        Block identityKey = deserializeBlock(buffer);
        Block signedPrekey = deserializeBlock(buffer);
        Block prekeySignature = deserializeBlock(buffer);

        this.key = DiffieHellman.decodePublicKey(deserializeBlock(buffer).getData());

        if(buffer.hasRemaining()) {
            Block onetimePrekey = deserializeBlock(buffer);

            bundle = new PrekeyBundle(identityKey, signedPrekey, prekeySignature, onetimePrekey);
        } else {
            bundle = new PrekeyBundle(identityKey, signedPrekey, prekeySignature);
        }
    }

    @Override
    protected byte[] serializeData() {
        byte[] identityKey = serializeBlock(bundle.getIdentityKey());
        byte[] signedPrekey = serializeBlock(bundle.getSignedPrekey());
        byte[] prekeySignature = serializeBlock(bundle.getPrekeySignature());
        byte[] key = serializeBlock(new Block(this.key.getEncoded()));

        Block otp = bundle.getOneTimePrekey();
        byte[] onetimePrekey = new byte[0];
        if(otp != null) {
            onetimePrekey = serializeBlock(bundle.getOneTimePrekey());
        }

        return ByteBuffer.allocate(identityKey.length + signedPrekey.length + prekeySignature.length + onetimePrekey.length + key.length)
                .put(identityKey)
                .put(signedPrekey)
                .put(prekeySignature)
                .put(key)
                .put(onetimePrekey)
                .array();
    }


}
