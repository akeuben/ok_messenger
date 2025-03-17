package org.ok.communication.packets;

import org.ok.communication.Packet;
import org.ok.protocols.Block;
import org.ok.protocols.doubleratchet.DoubleRatchetMessage;

import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

public class InboundMessagePacket extends Packet {
    public String destination;
    public Block data;
    public PublicKey pubKey;
    public long pn;
    public long n;

    public InboundMessagePacket() {
        super((byte) 0x01, (byte) 0x14);
    }

    public InboundMessagePacket(String destination, DoubleRatchetMessage message) {
        this();

        this.destination = destination;
        data = message.getData();
        pubKey = message.getHeader().getPubKey();
        pn = message.getHeader().getPn();
        n = message.getHeader().getN();
    }

    public InboundMessagePacket(byte[] rawPacket) {
        this();

        ByteBuffer buffer = ByteBuffer.wrap(rawPacket);

        this.destination = deserializeString(buffer);
        this.data = deserializeBlock(buffer);
        this.pubKey = (PublicKey) deserializeKey(buffer, "XDH", X509EncodedKeySpec.class);
        this.pn = buffer.getLong();
        this.n = buffer.getLong();
    }

    @Override
    protected byte[] serializeData() {

        byte[] destination = serializeString(this.destination);
        byte[] data = serializeBlock(this.data);
        byte[] pubKey = this.serializeKey(this.pubKey);

        return ByteBuffer.allocate(destination.length +
                        data.length +
                        pubKey.length +
                        Long.BYTES +
                        Long.BYTES)
                .put(destination)
                .put(data)
                .put(pubKey)
                .putLong(pn)
                .putLong(n)
                .array();
    }

}
