package org.ok.app;

import java.util.Map;

public interface ChatProvider {
    Chat getChat(String username);

    Map<String, Chat> getChats();

    boolean hasChat(String username);

    void addChat(String username, Chat chat);
}
