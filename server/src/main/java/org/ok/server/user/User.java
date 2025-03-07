package org.ok.server.user;

import org.ok.communication.Packet;
import org.ok.protocols.Block;

public interface User {
    String getUsername();
    Block getPasswordHash();

    boolean hasEnqueuedMessage();
    Packet getNextEnqueuedMessage();
}
