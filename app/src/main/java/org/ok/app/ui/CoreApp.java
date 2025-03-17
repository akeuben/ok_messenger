package org.ok.app.ui;

import org.ok.app.Chat;
import org.ok.protocols.Block;
import org.ok.protocols.diffiehellman.DiffieHellman;

import javax.swing.*;
import java.awt.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

public class CoreApp extends JFrame {

    public CoreApp() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        super("OK Messenger");

        setSize(600, 400);

        setLayout(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 0;
        c.weightx = 1;
        c.weighty = 1;
        c.fill = GridBagConstraints.BOTH;

        add(new ChatList(), c);

        c.gridx = 1;
        c.gridy = 0;
        c.weightx = 2;
        c.weighty = 1;
        c.fill = GridBagConstraints.BOTH;

        Block SK = Block.fromHexString("c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558");
        Block AD = Block.fromHexString("44116f1a6af9c79c123B8A12");

        KeyPair bobKeyPair = DiffieHellman.GenerateKeyPair();

        add(new CurrentChat(new Chat("other", SK, AD, bobKeyPair.getPublic())), c);

        setVisible(true);
    }
}
