package org.ok.communication.packets;

import org.ok.communication.Packet;
import org.ok.protocols.Block;
import org.ok.protocols.x3dh.PrekeyBundle;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class InboundUpdatePrekeysPacket extends Packet {
    public List<Block> prekeyBundles = new ArrayList<>();

    public InboundUpdatePrekeysPacket() {
        super((byte) 0x01, (byte) 0x15);
    }

    public InboundUpdatePrekeysPacket(Block[] bundles) {
        this();

        prekeyBundles.addAll(Arrays.asList(bundles));
    }

    public InboundUpdatePrekeysPacket(byte[] data) {
        this();

        ByteBuffer buffer = ByteBuffer.wrap(data);
        int count = buffer.getInt();
        for(int i = 0; i < count; i++) {
            prekeyBundles.add(deserializeBlock(buffer));
        }
    }

    @Override
    protected byte[] serializeData() {
        int size = 0;
        for(Block bundle : prekeyBundles) {
            size += bundle.getSizeBytes();
        }
        ByteBuffer buffer = ByteBuffer.allocate(size + prekeyBundles.size() * Integer.BYTES + Integer.BYTES);

        buffer.putInt(prekeyBundles.size());

        for(Block bundle : prekeyBundles) {
            buffer.put(serializeBlock(bundle));
        }

        return buffer.array();
    }


}
