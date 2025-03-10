package org.ok.communication;

import org.ok.protocols.Block;

import java.lang.reflect.InvocationTargetException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;

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

    protected byte[] serializeBlock(Block b) {
        int length = b.getSizeBytes();
        ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES + length);

        return buffer.putInt(length).put(b.getData()).array();
    }

    protected byte[] serializeKey(Key k) {
        byte[] data = k.getEncoded();
        int length = data.length;

        return ByteBuffer.allocate(Integer.BYTES + length).putInt(length).put(data).array();
    }

    protected byte[] serializeString(String s) {
        byte[] data = s.getBytes(StandardCharsets.UTF_8);
        int length = data.length;

        return ByteBuffer.allocate(Integer.BYTES + length).putInt(length).put(data).array();
    }

    protected Block deserializeBlock(ByteBuffer buffer) {
        int length = buffer.getInt();

        byte[] extracted = new byte[length];
        buffer.get(extracted, 0, length);
        return new Block(extracted);
    }

    protected Key deserializeKey(ByteBuffer buffer, String algrorithm, Class<? extends KeySpec> keySpec) {
        int length = buffer.getInt();

        byte[] extracted = new byte[length];
        buffer.get(extracted, 0, length);

        try {
            KeyFactory keyFactory = KeyFactory.getInstance(algrorithm);
            return keyFactory.generatePublic(keySpec.getConstructor(byte[].class).newInstance(extracted));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvocationTargetException |
                 InstantiationException | IllegalAccessException | NoSuchMethodException e) {
            throw new RuntimeException(e);
        }
    }

    protected String deserializeString(ByteBuffer buffer) {
        int length = buffer.getInt();
        byte[] data = new byte[length];
        buffer.get(data, 0, length);

        return new String(data, StandardCharsets.UTF_8);
    }

    public final byte getIdentifier() {
        return identifier;
    }

    public final byte getProtocolVersion() {
        return protocolVersion;
    }

    protected abstract byte[] serializeData();
}
