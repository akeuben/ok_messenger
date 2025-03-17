package org.ok.app;

import org.ok.communication.packets.InboundMessagePacket;
import org.ok.protocols.Block;
import org.ok.protocols.doubleratchet.DoubleRatchet;
import org.ok.protocols.doubleratchet.DoubleRatchetMessage;
import org.ok.protocols.x3dh.PrekeyBundle;

import javax.swing.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

public class Chat extends AbstractListModel<String> {
    public String user;
    public List<String> messages;
    DoubleRatchet dr;
    Block AD;

    public Chat(String user, Block SK, Block AD, PublicKey otherPublicKey) {
        this.user = user;
        this.messages = new ArrayList<>();
        this.dr = new DoubleRatchet(SK, otherPublicKey);
        this.AD = AD;
    }

    public Chat(String user, Block SK, Block AD, KeyPair myKeyPair) {
        this.user = user;
        this.messages = new ArrayList<>();
        this.dr = new DoubleRatchet(SK, myKeyPair);
        this.AD = AD;
    }

    public DoubleRatchetMessage encryptMessage(String message) {
        return dr.encrypt(new Block(message), AD);
    }

    public String decryptMessage(DoubleRatchetMessage message) {
        return new String(dr.decrypt(message, AD).getData(), StandardCharsets.UTF_8);
    }

    public void sendMessage(String message, Client client) {
        DoubleRatchetMessage msg = encryptMessage(message);

        this.messages.add("You: " + message);
        this.fireContentsChanged(messages, messages.size() - 1, messages.size() - 1);

        client.send(new InboundMessagePacket(user, msg).serialize());
    }

    public void recieveMessage(DoubleRatchetMessage message) {
        String msg = decryptMessage(message);

        this.messages.add(user + ": " + msg);
    }

    @Override
    public int getSize() {
        return messages.size();
    }

    @Override
    public String getElementAt(int index) {
        return messages.get(index);
    }
}
