package org.ok.server.user;

import org.ok.communication.Packet;
import org.ok.protocols.Block;
import org.ok.protocols.hmacsha256.SHA256;
import org.ok.protocols.x3dh.PrekeyBundle;
import org.ok.protocols.x3dh.X3DH;

import java.security.PublicKey;
import java.util.LinkedList;
import java.util.Queue;

public class InMemoryUser implements User{
    private String username;
    private Block passwordHash;
    private final Queue<Packet> enqueuedPackets = new LinkedList<>();

    private Block identityKey;
    private Block signedPrekey;
    private Block prekeySignature;
    private PublicKey dhPublicKey;

    public InMemoryUser(String username, String password) {
        this.username = username;
        this.passwordHash = new SHA256().sha256(new Block(password));
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public Block getPasswordHash() {
        return passwordHash;
    }

    @Override
    public boolean hasEnqueuedMessage() {
        return !enqueuedPackets.isEmpty();
    }

    @Override
    public Packet getNextEnqueuedMessage() {
        return enqueuedPackets.remove();
    }

    @Override
    public void enqueuePacket(Packet packet) {
        this.enqueuedPackets.add(packet);
    }

    @Override
    public boolean needsAdditionalPrekeys() {
        return false;
    }

    @Override
    public PrekeyBundle requestBundle() {
        return new PrekeyBundle(identityKey, signedPrekey, prekeySignature);
    }

    @Override
    public void updateKeys(Block identityKey, Block signedPrekey, Block prekeySignature, PublicKey dhPublicKey) {
        this.identityKey = identityKey;
        this.signedPrekey = signedPrekey;
        this.prekeySignature = prekeySignature;
        this.dhPublicKey = dhPublicKey;
    }

    @Override
    public PublicKey getDHPublicKey() {
        return this.dhPublicKey;
    }
}
