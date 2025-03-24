package org.ok.app;

import java.net.URI;

public class ClientManager {
    private static Client client;

    public static void connect() {
        client = new Client(URI.create("ws://127.0.0.1:1234"));
        client.connect();
    }

    public static void disconnect() {
        if(client == null) return;
        client.close();
        client = null;
    }

    public static void reconnect() {
        disconnect();
        connect();
    }

    public static Client get() {
        return client;
    }
}
