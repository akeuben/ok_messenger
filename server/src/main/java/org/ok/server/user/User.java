package org.ok.server.user;

import org.ok.communication.Packet;
import org.ok.protocols.Block;

public interface User {
    String getUsername();
    Block getPasswordHash();

    boolean hasEnqueuedMessage();
    Packet getNextEnqueuedMessage();

    void enqueuePacket(Packet packet);

    default boolean checkPassword(String password) {
        return getPasswordHash().equals(new Block(password));
    }
}
