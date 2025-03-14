package org.ok.app.ui;

import org.ok.app.App;
import org.ok.communication.packets.InboundLoginPacket;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class Login extends JFrame {

        JTextField username, password;

        public Login() {
            super("OK Messenger - Login");
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
            loginButton.addActionListener(e -> App.client.send(new InboundLoginPacket(username.getText(), password.getText()).serialize()));

            add(loginButton);
            setVisible(true);
        }
}
