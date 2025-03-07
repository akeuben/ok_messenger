package org.ok.communication;

import java.nio.ByteBuffer;

public abstract class Packet {

    private final byte protocolVersion;
    private final byte identifier;

    public Packet(byte protocolVersion, byte identifier) {
        this.protocolVersion = protocolVersion;
        this.identifier = identifier;
    }

    public byte[] serialize() {
        byte[] serializedData = serializeData();
        byte[] data = ByteBuffer.allocate(serializedData.length + 2)
                .put(protocolVersion)
                .put(identifier)
                .put(serializedData)
                .array();

        return data;
    }

    public final byte getIdentifier() {
        return identifier;
    }

    public final byte getProtocolVersion() {
        return protocolVersion;
    }

    protected abstract byte[] serializeData();
}
