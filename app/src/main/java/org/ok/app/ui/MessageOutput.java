package org.ok.app.ui;

import org.ok.app.Client;

import javax.swing.*;
import java.awt.*;

public class MessageOutput implements Runnable{
    private final Client client;
    private final JScrollPane scroll;
    private final JTextArea messageArea;

    public MessageOutput(Client client) {
        this.client = client;
        messageArea = new JTextArea();
        messageArea.setEditable(false);

        scroll = new JScrollPane(messageArea);

        Thread thread = new Thread(this);
        thread.start();
    }

    public JScrollPane getScroll() {
        return scroll;
    }

    @Override
    public void run() {
        //noinspection InfiniteLoopStatement
        while (true) {
            String[] messages = client.receiveQueue.getMessages();
            StringBuilder message = new StringBuilder();
            for(String msg : messages) {
                message.append(msg).append("\n");
            }
            if(!message.toString().isEmpty()) {
                messageArea.append(message.toString());
                messageArea.selectAll();
                int x = messageArea.getSelectionEnd();
                messageArea.select(x, x);
            }
        }
    }
}
