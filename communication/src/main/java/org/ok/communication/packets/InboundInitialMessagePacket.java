package org.ok.communication.packets;

import org.ok.communication.Packet;
import org.ok.protocols.Block;
import org.ok.protocols.x3dh.X3DHMessage;

import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

public class InboundInitialMessagePacket extends Packet {

    public String destination;
    public Block identityKey;
    public Block emphemeralKey;
    public long prekeyID;
    public Block data;
    public PublicKey pubKey;
    public long pn;
    public long n;

    public InboundInitialMessagePacket() {
        super((byte) 0x01, (byte) 0x13);
    }

    public InboundInitialMessagePacket(String destination, X3DHMessage message) {
        this();

        this.destination = destination;
        identityKey = message.getIdentityKey();
        emphemeralKey = message.getEmphemeralKey();
        prekeyID = message.getPrekeyID();
        data = message.getMessage().getData();
        pubKey = message.getMessage().getHeader().getPubKey();
        pn = message.getMessage().getHeader().getPn();
        n = message.getMessage().getHeader().getN();
    }

    public InboundInitialMessagePacket(byte[] rawPacket) {
        this();

        ByteBuffer buffer = ByteBuffer.wrap(rawPacket);

        destination = deserializeString(buffer);
        identityKey = deserializeBlock(buffer);
        emphemeralKey = deserializeBlock(buffer);
        prekeyID = buffer.getLong();
        data = deserializeBlock(buffer);
        pubKey = (PublicKey) deserializeKey(buffer, "XDH", X509EncodedKeySpec.class);
        pn = buffer.getLong();
        n = buffer.getLong();
    }

    @Override
    protected byte[] serializeData() {
        byte[] destination = serializeString(this.destination);
        byte[] identityKey = serializeBlock(this.identityKey);
        byte[] emphemeralKey = serializeBlock(this.emphemeralKey);
        byte[] data = serializeBlock(this.data);
        byte[] pubKey = serializeKey(this.pubKey);

        return ByteBuffer.allocate(destination.length + identityKey.length + emphemeralKey.length + Long.BYTES + data.length + pubKey.length + Long.BYTES + Long.BYTES)
                .put(destination)
                .put(identityKey)
                .put(emphemeralKey)
                .putLong(prekeyID)
                .put(data)
                .put(pubKey)
                .putLong(this.pn)
                .putLong(this.n)
                .array();
    }
}
