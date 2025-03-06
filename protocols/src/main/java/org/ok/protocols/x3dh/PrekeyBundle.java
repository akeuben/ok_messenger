package org.ok.protocols.x3dh;

import org.ok.protocols.Block;

public class PrekeyBundle {
    private Block identityKey;
    private Block signedPrekey;
    private Block prekeySignature;
    private Block oneTimePrekey;

    public PrekeyBundle(Block identityKey, Block signedPrekey, Block prekeySignature, Block oneTimePrekey) {
        this.identityKey = identityKey;
        this.signedPrekey = signedPrekey;
        this.prekeySignature = prekeySignature;
        this.oneTimePrekey = oneTimePrekey;
    }

    public PrekeyBundle(Block identityKey, Block signedPrekey, Block prekeySignature) {
        this(identityKey, signedPrekey, prekeySignature, null);
    }

    public Block getIdentityKey() {
        return identityKey;
    }

    public Block getSignedPrekey() {
        return signedPrekey;
    }

    public Block getPrekeySignature() {
        return prekeySignature;
    }

    public Block getOneTimePrekey() {
        return oneTimePrekey;
    }
}
