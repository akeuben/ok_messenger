package org.ok.server;

import org.ok.communication.PacketManager;
import org.ok.communication.packets.InboundLoginPacket;
import org.ok.communication.packets.OutboundLoginResponsePacket;
import org.ok.server.client.Client;

public class Main {
    public static void main(String[] args) {
        PacketManager<Client, Server> manager = PacketManager.getInstance();
        manager.register((byte) 0x02, InboundLoginPacket.class);
        manager.register((byte) 0x12, OutboundLoginResponsePacket.class);

        manager.addHandler(InboundLoginPacket.class, (p, s, r) -> {
            s.getConnection().send(new OutboundLoginResponsePacket(OutboundLoginResponsePacket.LoginResponseValue.INVALID_USER).serialize());
        });
        Server server = new Server(1234);
        server.start();

    }
}
