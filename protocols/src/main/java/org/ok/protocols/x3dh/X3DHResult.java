package org.ok.protocols.x3dh;

import org.ok.protocols.Block;

public class X3DHResult {
    private final Block SK;
    private final Block AD;
    private final Block ephemeralKey;

    public X3DHResult(Block SK, Block AD, Block ephemeralKey) {
        this.SK = SK;
        this.AD = AD;
        this.ephemeralKey = ephemeralKey;
    }

    public Block getSK() {
        return SK;
    }

    public Block getAD() {
        return AD;
    }

    public Block getEphemeralKey() {
        return ephemeralKey;
    }
}
