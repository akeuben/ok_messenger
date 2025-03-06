package org.ok.protocols.x3dh;

import org.ok.protocols.Block;
import org.ok.protocols.doubleratchet.DoubleRatchetMessage;

public class X3DHMessage {
    Block identityKey;
    Block emphemeralKey;
    long prekeyID;
    DoubleRatchetMessage message;

    public X3DHMessage(Block identityKey, Block emphemeralKey, long prekeyID, DoubleRatchetMessage message) {
        this.identityKey = identityKey;
        this.emphemeralKey = emphemeralKey;
        this.prekeyID = prekeyID;
        this.message = message;
    }

    public Block getIdentityKey() {
        return identityKey;
    }

    public Block getEmphemeralKey() {
        return emphemeralKey;
    }

    public long getPrekeyID() {
        return prekeyID;
    }

    public DoubleRatchetMessage getMessage() {
        return message;
    }
}
