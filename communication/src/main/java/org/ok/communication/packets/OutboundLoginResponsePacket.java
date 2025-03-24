package org.ok.communication.packets;

import org.ok.communication.Packet;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

public class OutboundLoginResponsePacket extends Packet {

    public enum LoginResponseValue {
        INVALID_USER((byte) 0x00),
        INVALID_PASSWORD((byte) 0x01),
        SUCCESS((byte) 0xFF);

        public final byte value;

        LoginResponseValue(byte value) {
            this.value = value;
        }

        public static LoginResponseValue fromValue(byte val) {
            for (LoginResponseValue e : values()) {
                if (e.value == val) {
                    return e;
                }
            }
            return null;
        }
    }

    public LoginResponseValue response;
    public String username;

    public OutboundLoginResponsePacket() {
        super((byte) 0x01, (byte) 0x12);
    }

    public OutboundLoginResponsePacket(LoginResponseValue response, String username) {
        this();

        this.response = response;
        this.username = username;
    }

    public OutboundLoginResponsePacket(byte[] rawData) {
        this();

        ByteBuffer buffer = ByteBuffer.wrap(rawData);

        this.username = deserializeString(buffer);
        this.response = LoginResponseValue.fromValue(buffer.get());
    }

    public LoginResponseValue getResponse() {
        return response;
    }

    @Override
    protected byte[] serializeData() {
        byte[] username = serializeString(this.username);
        ByteBuffer buffer = ByteBuffer.allocate(username.length + 1);
        return buffer.put(username).put(response.value).array();
    }

}
