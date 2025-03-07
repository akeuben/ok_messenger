package org.ok.communication;

import java.lang.reflect.InvocationTargetException;
import java.nio.ByteBuffer;
import java.util.HashMap;

public class PacketManager {
    private static final byte protocolVersion = 0x01;

    private static HashMap<Byte, Class<? extends Packet>> registeredPacketClasses = new HashMap<>();

    public static void register(byte identifier, Class<? extends Packet> packetClass) {
        registeredPacketClasses.put(identifier, packetClass);
    }

    public static Packet deserialize(byte[] rawPacket) {
        ByteBuffer packetBuffer = ByteBuffer.wrap(rawPacket);
        byte packetVersion = packetBuffer.get();
        byte packetIdentifier = packetBuffer.get();
        byte[] packetData = new byte[packetBuffer.remaining()];
        packetBuffer.get(packetData, 0, packetData.length);

        if(!registeredPacketClasses.containsKey(packetIdentifier)) {
            throw new RuntimeException("The specified packet was not registered");
        }

        if(packetVersion != protocolVersion) {
            throw new RuntimeException("The specified packet uses an unsupported version");
        }

        Class<? extends Packet> packetClass = registeredPacketClasses.get(packetIdentifier);
        try {
            return packetClass.getConstructor(byte[].class).newInstance(packetData);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
