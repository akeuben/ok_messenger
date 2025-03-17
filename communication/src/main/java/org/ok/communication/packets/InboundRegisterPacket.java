package org.ok.communication.packets;

import org.ok.communication.Packet;

import java.nio.ByteBuffer;

public class InboundRegisterPacket extends Packet {
    public String username;
    public String password;

    public InboundRegisterPacket() {
        super((byte) 0x01, (byte) 0x17);
    }

    public InboundRegisterPacket(String username, String password) {
        this();
        this.username = username;
        this.password = password;
    }

    public InboundRegisterPacket(byte[] data) {
        this();
        ByteBuffer buffer = ByteBuffer.wrap(data);
        this.username = deserializeString(buffer);
        this.password = deserializeString(buffer);
    }

    @Override
    protected byte[] serializeData() {
        byte[] usernameBytes = serializeString(username);
        byte[] passwordBytes = serializeString(password);
        ByteBuffer buffer = ByteBuffer.allocate(usernameBytes.length + passwordBytes.length);
        buffer.put(usernameBytes);
        buffer.put(passwordBytes);
        return buffer.array();
    }
}
