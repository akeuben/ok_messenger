package org.ok.communication.packets;

import org.ok.communication.Packet;

import java.nio.ByteBuffer;

public class OutboundRegisterResponsePacket extends Packet {
    public boolean success;

    public OutboundRegisterResponsePacket() {
        super((byte) 0x01, (byte) 0x18);
    }

    public OutboundRegisterResponsePacket(boolean success) {
        this();
        this.success = success;
    }

    public OutboundRegisterResponsePacket(byte[] data) {
        this();
        ByteBuffer buffer = ByteBuffer.wrap(data);
        this.success = buffer.get() == 1;
    }

    @Override
    protected byte[] serializeData() {
        return new byte[]{(byte) (success ? 1 : 0)};
    }
}
