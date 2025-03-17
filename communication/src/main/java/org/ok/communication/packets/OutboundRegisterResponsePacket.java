package org.ok.communication.packets;

import org.ok.communication.Packet;

import java.nio.ByteBuffer;

public class OutboundRegisterResponsePacket extends Packet {
    public boolean success;

    public OutboundRegisterResponsePacket(boolean success) {
        super((byte) 0x01, (byte) 0x18);
        this.success = success;
    }

    public OutboundRegisterResponsePacket(byte[] data) {
        super((byte) 0x01, (byte) 0x18);
        ByteBuffer buffer = ByteBuffer.wrap(data);
        this.success = buffer.get() == 1;
    }

    @Override
    protected byte[] serializeData() {
        return new byte[]{(byte) (success ? 1 : 0)};
    }
}
