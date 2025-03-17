package org.ok.server.user;

import org.ok.communication.Packet;
import org.ok.protocols.Block;
import org.ok.protocols.hmacsha256.SHA256;

public interface User {
    String getUsername();
    Block getPasswordHash();

    boolean hasEnqueuedMessage();
    Packet getNextEnqueuedMessage();

    void enqueuePacket(Packet packet);

    default boolean checkPassword(String password) {
        return getPasswordHash().equals(new SHA256().sha256(new Block(password)));
    }
}
