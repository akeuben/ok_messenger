package org.ok.app;

import java.util.ArrayList;

public class MessageQueue {
    private ArrayList<String> messages = new ArrayList<>();

    public synchronized String[] getMessages() {
        String[] messages = new String[0];
        messages = this.messages.toArray(messages);
        this.messages.clear();
        return messages;
    }

    public synchronized void addMessage(String message) {
        messages.add(message);
    }
}
