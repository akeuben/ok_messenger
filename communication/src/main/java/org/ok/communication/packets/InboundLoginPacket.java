package org.ok.communication.packets;

import org.ok.communication.Packet;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class InboundLoginPacket extends Packet {

    public final String username;
    public final String password;

    public InboundLoginPacket(String username, String password) {
        super((byte) 0x01, (byte) 0x02);

        this.username = username;
        this.password = password;
    }

    public InboundLoginPacket(byte[] data) {
        super((byte) 0x01, (byte) 0x02);

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
