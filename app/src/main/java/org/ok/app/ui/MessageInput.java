package org.ok.app.ui;

import org.ok.app.Client;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;

public class MessageInput extends JPanel implements ActionListener, KeyListener {

    private final JTextField field;

    private final Client client;

    public MessageInput(Client client) {
        this.client = client;
        field = new JTextField();
        field.addKeyListener(this);
        JButton sendButton = new JButton("Send");

        setLayout(new GridBagLayout());

        sendButton.addActionListener(this);

        GridBagConstraints csts = new GridBagConstraints();
        csts.gridx = 0;
        csts.gridy = 0;
        csts.fill = GridBagConstraints.HORIZONTAL;
        csts.weightx = 1;
        add(field, csts);
        csts.gridx = 1;
        csts.gridy = 0;
        csts.fill = GridBagConstraints.NONE;
        csts.weightx = 0;
        add(sendButton, csts);
    }

    private void send() {
        client.send(field.getText());
        field.setText("");
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        this.send();
    }

    @Override
    public void keyTyped(KeyEvent e) {

    }

    @Override
    public void keyPressed(KeyEvent e) {

    }

    @Override
    public void keyReleased(KeyEvent e) {
        if(e.getKeyCode() == KeyEvent.VK_ENTER) {
            this.send();
        }
    }
}
