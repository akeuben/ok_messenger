package org.ok.app.ui;

import org.ok.app.*;
import org.ok.protocols.Block;
import org.ok.protocols.diffiehellman.DiffieHellman;

import javax.swing.*;
import java.awt.*;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

public class CoreApp extends JFrame implements WindowListener {

    CurrentChat chat;

    public CoreApp() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        super("OK Messenger: " + App.username);
        addWindowListener(this);

        setSize(600, 400);

        setLayout(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 0;
        c.weightx = 1;
        c.weighty = 1;
        c.fill = GridBagConstraints.BOTH;

        chat = new CurrentChat(null);

        add(new ChatList((s -> {
            chat.setChat(ChatManager.getInstance().getChat(s));
            revalidate();
            repaint();
            chat.revalidate();
            chat.repaint();
        })), c);

        c.gridx = 1;
        c.gridy = 0;
        c.weightx = 2;
        c.weighty = 1;
        c.fill = GridBagConstraints.BOTH;

        add(chat, c);

        setVisible(true);
    }

    @Override
    public void windowOpened(WindowEvent e) {

    }

    @Override
    public void windowClosing(WindowEvent e) {
        ClientManager.reconnect();
        WindowManager.set(new Login());
    }

    @Override
    public void windowClosed(WindowEvent e) {

    }

    @Override
    public void windowIconified(WindowEvent e) {

    }

    @Override
    public void windowDeiconified(WindowEvent e) {

    }

    @Override
    public void windowActivated(WindowEvent e) {

    }

    @Override
    public void windowDeactivated(WindowEvent e) {

    }
}
