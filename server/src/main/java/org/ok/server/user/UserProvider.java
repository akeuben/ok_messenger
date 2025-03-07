package org.ok.server.user;

public interface UserProvider {
    User getUser(String username);
    boolean exists(String username);
    void createUser(String username, String password);
}
