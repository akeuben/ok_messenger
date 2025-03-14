package org.ok.communication;

@FunctionalInterface
public interface PacketHandler<T extends Packet, S, R> {
    void handlePacket(T packet, S sender, R reciever);
}
