package org.ok.app.ui;

import org.ok.app.App;
import org.ok.app.Chat;

import javax.swing.*;
import java.awt.*;

public class CurrentChat extends JPanel {
    private Chat chat;

    public CurrentChat(Chat chat) {
        super();
        setLayout(new GridBagLayout());
        this.chat = chat;

        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 0;
        c.weightx = 1;
        c.weighty = 1;
        c.fill = GridBagConstraints.BOTH;

        JList<String> messages = new JList<>(chat);
        JScrollPane pane = new JScrollPane(messages);

        add(pane, c);

        JPanel panel = new JPanel();
        panel.setLayout(new GridBagLayout());

        JTextField messageField = new JTextField();
        c.gridx = 0;
        c.gridy = 0;
        c.weightx = 1;
        c.weighty = 0;
        c.fill = GridBagConstraints.HORIZONTAL;
        panel.add(messageField, c);

        JButton sendButton = new JButton("Send");
        c.gridx = 1;
        c.gridy = 0;
        c.weightx = 0;
        c.weighty = 0;
        c.fill = GridBagConstraints.NONE;
        sendButton.addActionListener(e -> {
            chat.sendMessage(messageField.getText(), App.client);
        });

        panel.add(sendButton, c);

        c.gridx = 0;
        c.gridy = 1;
        c.weightx = 1;
        c.weighty = 0;
        c.fill = GridBagConstraints.HORIZONTAL;
        add(panel, c);

    }


}
