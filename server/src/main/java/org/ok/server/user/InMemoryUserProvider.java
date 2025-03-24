package org.ok.server.user;

import java.util.HashMap;
import java.util.Map;

public class InMemoryUserProvider implements UserProvider {

    private Map<String, User> users = new HashMap<>();

    @Override
    public User getUser(String username) {
        return users.get(username);
    }

    @Override
    public boolean exists(String username) {
        return users.containsKey(username);
    }

    @Override
    public void createUser(String username, String password) {
        if(users.containsKey(username)) {
            throw new RuntimeException("User already exists");
        }

        users.put(username, new InMemoryUser(username, password));
    }
}
