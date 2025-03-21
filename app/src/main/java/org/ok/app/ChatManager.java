package org.ok.app;

import javax.swing.*;
import java.util.AbstractList;
import java.util.HashMap;
import java.util.Map;

public class ChatManager extends AbstractListModel<String> implements ChatProvider {
    private static ChatManager instance;
    private ChatProvider provider;

    public static void init(ChatProvider provider) {
        instance = new ChatManager(provider);
    }

    public static ChatManager getInstance() {
        return instance;
    }

    private ChatManager(ChatProvider provider) {
        this.provider = provider;
    }

    @Override
    public Chat getChat(String username) {
        return provider.getChat(username);
    }

    @Override
    public Map<String, Chat> getChats() {
        return provider.getChats();
    }

    @Override
    public boolean hasChat(String username) {
        return provider.hasChat(username);
    }

    @Override
    public void addChat(String username, Chat chat) {
        provider.addChat(username, chat);

        this.fireContentsChanged(this, 0, getSize() - 1);
    }

    @Override
    public String getElementAt(int index) {
        return (String) getChats().keySet().toArray()[index];
    }

    @Override
    public int getSize() {
        return getChats().size();
    }
}
