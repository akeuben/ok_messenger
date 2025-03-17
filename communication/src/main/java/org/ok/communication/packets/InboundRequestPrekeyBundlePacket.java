package org.ok.communication.packets;

import org.ok.communication.Packet;

import java.nio.ByteBuffer;

public class InboundRequestPrekeyBundlePacket extends Packet {

    public String user;

    public InboundRequestPrekeyBundlePacket(String user) {
        super((byte) 0x01, (byte) 0x16);

        this.user = user;
    }

    public InboundRequestPrekeyBundlePacket(byte[] data) {
        super((byte) 0x01, (byte) 0x16);
        ByteBuffer buffer = ByteBuffer.wrap(data);

        this.user = deserializeString(buffer);
    }

    @Override
    protected byte[] serializeData() {
        return serializeString(this.user);
    }
}
