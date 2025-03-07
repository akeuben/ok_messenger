package org.ok.communication.packets;

import org.ok.communication.Packet;
import org.ok.protocols.Block;
import org.ok.protocols.diffiehellman.DiffieHellman;
import org.ok.protocols.doubleratchet.DoubleRatchetMessage;

import java.nio.ByteBuffer;
import java.security.PublicKey;

public class OutboundMessagePacket extends Packet {
    public final Block data;
    public final PublicKey pubKey;
    public final long pn;
    public final long n;


    public OutboundMessagePacket(DoubleRatchetMessage message) {
        super((byte) 0x01, (byte) 0x04);

        data = message.getData();
        pubKey = message.getHeader().getPubKey();
        pn = message.getHeader().getPn();
        n = message.getHeader().getN();
    }

    public OutboundMessagePacket(byte[] rawPacket) {
        super((byte) 0x01, (byte) 0x04);

        ByteBuffer buffer = ByteBuffer.wrap(rawPacket);

        int dataLength = buffer.getInt();
        byte[] data = new byte[dataLength];
        buffer.get(data, 0, dataLength);
        this.data = new Block(data);

        int pubKeyLength = buffer.getInt();
        byte[] pubKey = new byte[pubKeyLength];
        buffer.get(pubKey, 0, pubKeyLength);
        this.pubKey = DiffieHellman.decodePublicKey(pubKey);

        this.pn = buffer.getLong();
        this.n = buffer.getLong();
    }

    @Override
    protected byte[] serializeData() {

        int dataLength = data.getSizeBytes();
        byte[] data = this.data.getData();

        byte[] pubKey = this.pubKey.getEncoded();
        int pubKeyLength = pubKey.length;

        return ByteBuffer.allocate(Integer.BYTES + dataLength +
                        Integer.BYTES + pubKeyLength +
                        Long.BYTES +
                        Long.BYTES)
                .putInt(dataLength)
                .put(data)
                .putInt(pubKeyLength)
                .put(pubKey)
                .putLong(pn)
                .putLong(n)
                .array();
    }
}
