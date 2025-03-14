package org.ok.server.client;

import org.java_websocket.WebSocket;
import org.ok.communication.Packet;
import org.ok.protocols.Block;
import org.ok.protocols.hmacsha256.SHA256;
import org.ok.server.user.User;
import org.ok.server.user.UserManager;

public class Client {
    private static SHA256 sha = new SHA256();
    private ClientState state;
    private User user;

    private WebSocket connection;

    public Client(WebSocket connection) {
        this.connection = connection;
    }

    public void connect(WebSocket connection) {
        if(this.state != ClientState.DISCONNECTED) {
            throw new RuntimeException("Client must be disconnected in order to connect");
        }

        this.connection = connection;
        this.state = ClientState.CONNECTED;
    }

    public void disconnect() {
        this.connection = null;
        this.state = ClientState.DISCONNECTED;
    }

    public boolean authenticate(String username, String password) {
        if(this.state != ClientState.CONNECTED) {
            throw new RuntimeException("Client is either disconnected or is already authenticated");
        }
        this.user = UserManager.getInstance().getUser(username);

        if(this.user == null) {
            return false;
        }

        if(this.user.getPasswordHash() != sha.sha256(new Block(password))) {
            return false;
        }

        this.state = ClientState.AUTHENTICATED;

        return true;
    }

    public WebSocket getConnection() {
        return connection;
    }

    public User getUser() {
        return user;
    }
}
