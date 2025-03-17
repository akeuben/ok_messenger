package org.ok.server;

import org.ok.communication.PacketManager;
import org.ok.communication.packets.*;
import org.ok.server.client.Client;
import org.ok.server.user.InMemoryUserProvider;
import org.ok.server.user.UserManager;

public class Main {
    public static void main(String[] args) {
        UserManager.init(new InMemoryUserProvider());
        PacketManager<Client, Server> manager = PacketManager.getInstance();
        manager.register(InboundLoginPacket.class);
        manager.register(OutboundLoginResponsePacket.class);
        manager.register(InboundInitialMessagePacket.class);
        manager.register(InboundLoginPacket.class);
        manager.register(InboundMessagePacket.class);
        manager.register(InboundRegisterPacket.class);
        manager.register(InboundRequestPrekeyBundlePacket.class);
        manager.register(InboundUpdatePrekeysPacket.class);
        manager.register(OutboundInitialMessagePacket.class);
        manager.register(OutboundLoginResponsePacket.class);
        manager.register(OutboundMessagePacket.class);
        manager.register(OutboundPrekeyBundlePacket.class);
        manager.register(OutboundRegisterResponsePacket.class);
        manager.register(OutboundRequestPrekeysPacket.class);

        manager.addHandler(InboundLoginPacket.class, (p, s, r) -> {
            OutboundLoginResponsePacket.LoginResponseValue res = s.authenticate(p.username, p.password);
            s.Send(new OutboundLoginResponsePacket(res));
        });

        manager.addHandler(InboundRegisterPacket.class, (p, s, r) -> {
            try {
                UserManager.getInstance().createUser(p.username, p.password);
                s.Send(new OutboundRegisterResponsePacket(true));
            } catch (RuntimeException e) {
                s.Send(new OutboundRegisterResponsePacket(false));
            }

        });
        Server server = new Server(1234);
        server.start();

    }
}
