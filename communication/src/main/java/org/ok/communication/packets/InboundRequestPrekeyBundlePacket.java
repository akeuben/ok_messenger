package org.ok.communication.packets;

import org.ok.communication.Packet;

import java.nio.ByteBuffer;

public class InboundRequestPrekeyBundlePacket extends Packet {

    public String user;

    public InboundRequestPrekeyBundlePacket() {
        super((byte) 0x01, (byte) 0x16);
    }

    public InboundRequestPrekeyBundlePacket(String user) {
        this();

        this.user = user;
    }

    public InboundRequestPrekeyBundlePacket(byte[] data) {
        this();
        ByteBuffer buffer = ByteBuffer.wrap(data);

        this.user = deserializeString(buffer);
    }

    @Override
    protected byte[] serializeData() {
        return serializeString(this.user);
    }
}
