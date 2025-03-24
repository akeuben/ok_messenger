package org.ok.app;

import java.util.HashMap;
import java.util.Map;

public class InMemoryChatProvider implements ChatProvider {

    Map<String, Chat> chats = new HashMap<>();

    @Override
    public Chat getChat(String username) {
        return chats.get(username);
    }

    @Override
    public Map<String, Chat> getChats() {
        return chats;
    }

    @Override
    public boolean hasChat(String username) {
        return chats.containsKey(username);
    }

    @Override
    public void addChat(String username, Chat chat) {
        chats.put(username, chat);
    }
}
