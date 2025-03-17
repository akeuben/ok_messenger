package org.ok.server.user;

import org.ok.communication.Packet;
import org.ok.protocols.Block;
import org.ok.protocols.hmacsha256.SHA256;

import java.util.LinkedList;
import java.util.Queue;

public class InMemoryUser implements User{
    private String username;
    private Block passwordHash;
    private final Queue<Packet> enqueuedPackets = new LinkedList<>();

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
}
