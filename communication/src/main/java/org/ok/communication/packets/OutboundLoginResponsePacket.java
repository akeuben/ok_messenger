package org.ok.communication.packets;

import org.ok.communication.Packet;

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

    public OutboundLoginResponsePacket() {
        super((byte) 0x01, (byte) 0x12);
    }

    public OutboundLoginResponsePacket(LoginResponseValue response) {
        this();

        this.response = response;
    }

    public OutboundLoginResponsePacket(byte[] rawData) {
        this();

        this.response = LoginResponseValue.fromValue(rawData[0]);
    }

    public LoginResponseValue getResponse() {
        return response;
    }

    @Override
    protected byte[] serializeData() {
        return new byte[] {response.value};
    }

}
