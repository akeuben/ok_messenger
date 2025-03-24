package org.ok.app.ui;

import org.ok.app.App;
import org.ok.app.ClientManager;
import org.ok.communication.packets.InboundLoginPacket;
import org.ok.communication.packets.InboundRegisterPacket;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;

public class Login extends JFrame implements WindowListener {

        JTextField username, password;

        public Login() {
            super("OK Messenger - Login");
            addWindowListener(this);
            setSize(800, 600);
            setLayout(new BoxLayout(this.getContentPane(), BoxLayout.Y_AXIS));

            JLabel label = new JLabel("Login");
            label.setHorizontalAlignment(JLabel.CENTER);
            add(label);

            username = new JTextField();
            password = new JTextField();

            add(username);
            add(password);

            JButton loginButton = new JButton("Login");
            loginButton.addActionListener(e -> ClientManager.get().send(new InboundLoginPacket(username.getText(), password.getText()).serialize()));

            add(loginButton);

            JButton registerButton = new JButton("Register");
            registerButton.addActionListener(e -> ClientManager.get().send(new InboundRegisterPacket(username.getText(), password.getText()).serialize()));

            add(registerButton);
            setVisible(true);
        }

    @Override
    public void windowOpened(WindowEvent e) {

    }

    @Override
    public void windowClosing(WindowEvent e) {
        App.exit();
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
