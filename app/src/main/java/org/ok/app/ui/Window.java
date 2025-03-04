package org.ok.app.ui;

import org.ok.app.Client;

import javax.swing.*;
import java.awt.*;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import java.util.Arrays;

public class Window extends JFrame implements Runnable, WindowListener {
    private Client client;

    private volatile boolean open = true;

    public Window(Client client) {
        super("OK Messenger");
        this.client = client;

        GridBagLayout layout = new GridBagLayout();
        setLayout(layout);

        GridBagConstraints csts = new GridBagConstraints();
        csts.gridx = 0;
        csts.gridy = 0;
        csts.weightx = 2;
        csts.weighty = 2;
        csts.fill = GridBagConstraints.BOTH;
        add(new MessageOutput(client).getScroll(), csts);

        MessageInput input = new MessageInput(client);
        csts.gridx = 0;
        csts.gridy = 1;
        csts.weightx = 2;
        csts.weighty = 0;
        csts.fill = GridBagConstraints.HORIZONTAL;
        add(input, csts);

        addWindowListener(this);
        setVisible(true);
        setSize(500, 500);
    }

    @Override
    public void run() {
    }

    @Override
    public void windowOpened(WindowEvent e) {

    }

    @Override
    public void windowClosing(WindowEvent e) {
        System.out.println("Window closed");
        client.close();
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
