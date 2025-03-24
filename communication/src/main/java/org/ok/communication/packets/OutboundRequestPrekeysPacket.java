package org.ok.communication.packets;

import org.ok.communication.Packet;

public class OutboundRequestPrekeysPacket extends Packet {

    public OutboundRequestPrekeysPacket() {
        super((byte) 0x01, (byte)0x05);
    }

    public OutboundRequestPrekeysPacket(byte[] ignored) {
        this();
    }

    @Override
    protected byte[] serializeData() {
        return new byte[0];
    }
}
