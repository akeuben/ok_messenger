package org.ok.communication.packets;

import org.ok.communication.Packet;
import org.ok.protocols.Block;
import org.ok.protocols.doubleratchet.DoubleRatchetMessage;

import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

public class OutboundMessagePacket extends Packet {
    public String origin;
    public Block data;
    public PublicKey pubKey;
    public long pn;
    public long n;

    public OutboundMessagePacket() {
        super((byte) 0x01, (byte) 0x04);
    }

    public OutboundMessagePacket(String origin, DoubleRatchetMessage message) {
        this();

        this.origin = origin;
        data = message.getData();
        pubKey = message.getHeader().getPubKey();
        pn = message.getHeader().getPn();
        n = message.getHeader().getN();
    }

    public OutboundMessagePacket(byte[] rawPacket) {
        this();

        ByteBuffer buffer = ByteBuffer.wrap(rawPacket);

        this.origin = deserializeString(buffer);
        this.data = deserializeBlock(buffer);
        this.pubKey = (PublicKey) deserializeKey(buffer, "XDH", X509EncodedKeySpec.class);
        this.pn = buffer.getLong();
        this.n = buffer.getLong();
    }

    @Override
    protected byte[] serializeData() {

        byte[] origin = serializeString(this.origin);
        byte[] data = serializeBlock(this.data);
        byte[] pubKey = this.serializeKey(this.pubKey);

        return ByteBuffer.allocate(origin.length +
                        data.length +
                        pubKey.length +
                        Long.BYTES +
                        Long.BYTES)
                .put(origin)
                .put(data)
                .put(pubKey)
                .putLong(pn)
                .putLong(n)
                .array();
    }
}
