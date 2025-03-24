package org.ok.server;

import org.ok.communication.PacketManager;
import org.ok.communication.packets.*;
import org.ok.protocols.x3dh.PrekeyBundle;
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
        manager.register(InboundUpdateKeysPacket.class);
        manager.register(NoSuchUserPacket.class);

        manager.addHandler(InboundLoginPacket.class, (p, s, r) -> {
            OutboundLoginResponsePacket.LoginResponseValue res = s.authenticate(p.username, p.password);
            s.Send(new OutboundLoginResponsePacket(res, p.username));

            if(s.getUser().needsAdditionalPrekeys()) {

            }
        });

        manager.addHandler(InboundRegisterPacket.class, (p, s, r) -> {
            try {
                UserManager.getInstance().createUser(p.username, p.password);
                s.Send(new OutboundRegisterResponsePacket(true));
            } catch (RuntimeException e) {
                s.Send(new OutboundRegisterResponsePacket(false));
            }

        });

        manager.addHandler(InboundUpdateKeysPacket.class, (p, s, r) -> {
            s.getUser().updateKeys(p.identityKey, p.signedPrekey, p.prekeySignature, p.dhPublicKey);
        });

        manager.addHandler(InboundRequestPrekeyBundlePacket.class, (p, s, r) -> {
            if(UserManager.getInstance().exists(p.user)) {
                PrekeyBundle bundle = UserManager.getInstance().getUser(p.user).requestBundle();
                s.Send(new OutboundPrekeyBundlePacket(bundle, UserManager.getInstance().getUser(p.user).getDHPublicKey()));
            } else {
                s.Send(new NoSuchUserPacket());
            }
        });

        manager.addHandler(InboundInitialMessagePacket.class, (p, s, r) -> {
            if(p.destination.equals(s.getUser().getUsername())) {
                s.Send(new OutboundMessagePacket(s.getUser().getUsername(), p.getMessage().getMessage()));
            } else {
                Client dest = r.getClient(p.destination);
                if(dest != null) {
                    dest.Send(new OutboundInitialMessagePacket(s.getUser().getUsername(), p.getMessage()));
                } else {
                    // TODO: Add to message queue
                }
            }
        });

        manager.addHandler(InboundMessagePacket.class, (p, s, r) -> {
            Client dest = r.getClient(p.destination);
            if(dest != null) {
                dest.Send(new OutboundMessagePacket(s.getUser().getUsername(), p.getMessage()));
            } else {
                // TODO: Add to message queue
            }
        });

        Server server = new Server(1234);
        server.start();

    }
}
