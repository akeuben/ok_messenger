package org.ok.server.user;

import org.ok.communication.Packet;
import org.ok.protocols.Block;
import org.ok.protocols.hmacsha256.SHA256;
import org.ok.protocols.x3dh.PrekeyBundle;

import java.security.PublicKey;

public interface User {
    String getUsername();
    Block getPasswordHash();

    boolean hasEnqueuedMessage();
    Packet getNextEnqueuedMessage();

    void enqueuePacket(Packet packet);

    default boolean checkPassword(String password) {
        return getPasswordHash().equals(SHA256.sha256(new Block(password)));
    }

    boolean needsAdditionalPrekeys();
    PrekeyBundle requestBundle();

    void updateKeys(Block identityKey, Block signedPrekey, Block prekeySignature, PublicKey key);

    PublicKey getDHPublicKey();
}
