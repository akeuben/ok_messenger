package org.ok.communication.packets;

import org.ok.communication.Packet;

public class NoSuchUserPacket extends Packet {
    public NoSuchUserPacket() {
        super((byte) 0x01, (byte) 0x21);
    }

    public NoSuchUserPacket(byte[] data) {
        this();
    }

    @Override
    protected byte[] serializeData() {
        return new byte[0];
    }
}
