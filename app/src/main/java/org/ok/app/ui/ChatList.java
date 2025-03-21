package org.ok.app.ui;

import org.ok.app.*;
import org.ok.communication.PacketManager;
import org.ok.communication.packets.InboundRequestPrekeyBundlePacket;
import org.ok.communication.packets.NoSuchUserPacket;
import org.ok.communication.packets.OutboundPrekeyBundlePacket;
import org.ok.protocols.Block;
import org.ok.protocols.x3dh.X3DH;
import org.ok.protocols.x3dh.X3DHResult;

import javax.swing.*;
import java.awt.*;
import java.security.KeyPair;
import java.util.function.Consumer;

public class ChatList extends JPanel {
    public ChatList(Consumer<String> onChatSelected) {
        super();
        setLayout(new GridBagLayout());

        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 0;
        c.weightx = 0;
        c.weighty = 0;
        c.fill = GridBagConstraints.NONE;

        JButton newChatButton = createNewChatButton();
        add(newChatButton, c);

        JList<String> list = new JList<>(ChatManager.getInstance());
        JScrollPane pane = new JScrollPane(list);

        c.gridx = 0;
        c.gridy = 1;
        c.weightx = 1;
        c.weighty = 1;
        c.fill = GridBagConstraints.BOTH;

        list.addListSelectionListener((e) -> {
            onChatSelected.accept(list.getSelectedValue());
        });

        add(pane, c);
    }

    private static JButton createNewChatButton() {
        JButton newChatButton = new JButton("New Chat");
        newChatButton.addActionListener(e -> {
            String username = JOptionPane.showInputDialog(WindowManager.get(), "Enter Username", "New Chat Wizard", JOptionPane.QUESTION_MESSAGE);
            PacketManager.getInstance().addOneShotHandler(OutboundPrekeyBundlePacket.class, (p, s, r) -> {
                String message = JOptionPane.showInputDialog(WindowManager.get(), "Enter First Message", "New Chat Wizard", JOptionPane.QUESTION_MESSAGE);

                X3DHResult result = X3DH.runSend(p.bundle, SecretManager.getInstance().x3DHKeyPair());
                System.out.println("Got the public DH key: " + new Block(p.key));

                Chat chat = new Chat(username, result.getSK(), result.getAD(), p.key);
                ChatManager.getInstance().addChat(username, chat);
                chat.sendInitialMessage(message, result, ClientManager.get());
            });
            PacketManager.getInstance().addOneShotHandler(NoSuchUserPacket.class, (p, s, r) -> {
                JOptionPane.showMessageDialog(WindowManager.get(), "No such user", "New Chat Wizard", JOptionPane.ERROR_MESSAGE);
            });
            ClientManager.get().send(new InboundRequestPrekeyBundlePacket(username).serialize());
        });
        return newChatButton;
    }
}
