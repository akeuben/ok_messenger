package org.ok.communication.packets;

import org.ok.communication.Packet;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class InboundLoginPacket extends Packet {

    public String username;
    public String password;

    public InboundLoginPacket() {
        super((byte) 0x01, (byte) 0x02);
    }

    public InboundLoginPacket(String username, String password) {
        this();

        this.username = username;
        this.password = password;
    }

    public InboundLoginPacket(byte[] data) {
        this();

        ByteBuffer buffer = ByteBuffer.wrap(data);

        this.username = deserializeString(buffer);
        this.password = deserializeString(buffer);
    }

    @Override
    protected byte[] serializeData() {
        byte[] encodedUsername = serializeString(this.username);
        byte[] encodedPassword = serializeString(this.password);

        return ByteBuffer.allocate(encodedUsername.length + encodedPassword.length)
                .put(encodedUsername)
                .put(encodedPassword).array();
    }
}
