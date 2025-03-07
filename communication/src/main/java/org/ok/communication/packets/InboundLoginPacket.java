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
        int usernameLength = buffer.getInt();
        int passwordLength = buffer.getInt();

        byte[] username = new byte[usernameLength];
        byte[] password = new byte[passwordLength];

        buffer.get(username, 0, usernameLength);
        buffer.get(password, 0, passwordLength);

        this.username = new String(username, StandardCharsets.UTF_8);
        this.password = new String(password, StandardCharsets.UTF_8);
    }

    @Override
    protected byte[] serializeData() {
        byte[] encodedUsername = username.getBytes(StandardCharsets.UTF_8);
        byte[] encodedPassword = password.getBytes(StandardCharsets.UTF_8);

        return ByteBuffer.allocate(encodedUsername.length + encodedPassword.length + Integer.BYTES + Integer.BYTES)
                .putInt(encodedUsername.length)
                .putInt(encodedPassword.length)
                .put(encodedUsername)
                .put(encodedPassword).array();
    }
}
