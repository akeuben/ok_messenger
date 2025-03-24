package org.ok.communication.packets;

import org.ok.communication.Packet;
import org.ok.protocols.Block;
import org.ok.protocols.diffiehellman.DiffieHellman;
import org.ok.protocols.x3dh.PrekeyBundle;

import java.nio.ByteBuffer;
import java.security.PublicKey;

public class InboundUpdateKeysPacket extends Packet {
    public Block identityKey;
    public Block signedPrekey;
    public Block prekeySignature;
    public PublicKey dhPublicKey;

    public InboundUpdateKeysPacket() {
        super((byte) 0x01, (byte) 0x20);
    }

    public InboundUpdateKeysPacket(Block identityKey, Block signedPrekey, Block prekeySignature, PublicKey dhPublicKey) {
        this();

        this.identityKey = identityKey;
        this.signedPrekey = signedPrekey;
        this.prekeySignature = prekeySignature;
        this.dhPublicKey = dhPublicKey;
    }

    public InboundUpdateKeysPacket(PrekeyBundle bundle, PublicKey dhPublicKey) {
        this();
        this.identityKey = bundle.getIdentityKey();
        this.signedPrekey = bundle.getSignedPrekey();
        this.prekeySignature = bundle.getPrekeySignature();
        this.dhPublicKey = dhPublicKey;
    }

    public InboundUpdateKeysPacket(byte[] rawData) {
        this();
        ByteBuffer buffer = ByteBuffer.wrap(rawData);

        this.identityKey = deserializeBlock(buffer);
        this.signedPrekey = deserializeBlock(buffer);
        this.prekeySignature = deserializeBlock(buffer);
        this.dhPublicKey = DiffieHellman.decodePublicKey(deserializeBlock(buffer).getData());
    }

    @Override
    protected byte[] serializeData() {
        byte[] identityKey = serializeBlock(this.identityKey);
        byte[] signedPrekey = serializeBlock(this.signedPrekey);
        byte[] prekeySignature = serializeBlock(this.prekeySignature);
        byte[] key = serializeBlock(new Block(this.dhPublicKey.getEncoded()));

        return ByteBuffer.allocate(identityKey.length + signedPrekey.length + prekeySignature.length + key.length)
                .put(identityKey)
                .put(signedPrekey)
                .put(prekeySignature)
                .put(key)
                .array();
    }
}
