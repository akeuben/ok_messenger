package org.ok.communication;

import java.lang.reflect.InvocationTargetException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class PacketManager<S,R> {
    private static PacketManager<?,?> instance;
    private static final byte protocolVersion = 0x01;

    private final HashMap<Byte, Class<? extends Packet>> registeredPacketClasses = new HashMap<>();
    private final HashMap<Class<? extends Packet>, List<PacketHandler<?, S, R>>> handlers = new HashMap<>();
    private final HashMap<Class<? extends Packet>, List<PacketHandler<?, S, R>>> oneTimeHandlers = new HashMap<>();

    public void register(byte identifier, Class<? extends Packet> packetClass) {
        registeredPacketClasses.put(identifier, packetClass);
    }

    public void register(Class<? extends Packet> packetClass) {
        try {
            Packet packet = packetClass.getConstructor().newInstance();
            register(packet.getIdentifier(), packetClass);
        } catch (InstantiationException | IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
            throw new RuntimeException(e);
        }

    }

    public static <S, R> PacketManager<S,R> getInstance() {
        if(instance == null) {
            instance = new PacketManager<S, R>();
        }
        //noinspection unchecked
        return (PacketManager<S, R>) instance;
    }

    public Packet deserialize(byte[] rawPacket) {
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

    public <T extends Packet> void addHandler(Class<T> clazz, PacketHandler<T,S,R> handler) {
        if(!handlers.containsKey(clazz)) {
            handlers.put(clazz, new ArrayList<>());
        }
        handlers.get(clazz).add(handler);
    }

    public <T extends Packet> void addOneShotHandler(Class<T> clazz, PacketHandler<T,S,R> handler) {
        if(!oneTimeHandlers.containsKey(clazz)) {
            oneTimeHandlers.put(clazz, new ArrayList<>());
        }
        oneTimeHandlers.get(clazz).add(handler);
    }

    public <T extends Packet> void handle(T packet, S sender, R receiver) {
        List<PacketHandler<? extends Packet, S, R>> packetHandlers = handlers.get(packet.getClass());
        if(packetHandlers != null) {
            for (PacketHandler<? extends Packet, S, R> handler : packetHandlers) {
                //noinspection unchecked
                ((PacketHandler<T, S, R>) handler).handlePacket(packet, sender, receiver);
            }
        }
        packetHandlers = oneTimeHandlers.get(packet.getClass());
        if(packetHandlers != null) {
            for (PacketHandler<? extends Packet, S, R> handler : packetHandlers) {
                //noinspection unchecked
                ((PacketHandler<T, S, R>) handler).handlePacket(packet, sender, receiver);
            }
            packetHandlers.clear();
        }
    }

    public void handle(byte[] rawPacket, S sender, R receiver) {
        Packet packet = deserialize(rawPacket);
        Class<? extends Packet> packetClass = registeredPacketClasses.get(packet.getIdentifier());
        handle(packetClass.cast(packet), sender, receiver);
    }
}
