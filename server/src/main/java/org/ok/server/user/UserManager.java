package org.ok.server.user;

public class UserManager implements UserProvider {
    private static UserManager instance;

    private final UserProvider provider;

    private UserManager(UserProvider provider) {
        this.provider = provider;
    }

    public static void init(UserProvider provider) {
        instance = new UserManager(provider);
    }

    public static UserManager getInstance() {
        return instance;
    }

    @Override
    public User getUser(String username) {
        return provider.getUser(username);
    }

    @Override
    public boolean exists(String username) {
        return provider.exists(username);
    }

    @Override
    public void createUser(String username, String password) {
        provider.createUser(username, password);
    }
}
