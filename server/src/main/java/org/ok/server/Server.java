package org.ok.server;

import org.java_websocket.WebSocket;
import org.java_websocket.handshake.ClientHandshake;
import org.java_websocket.server.WebSocketServer;
import org.ok.communication.Packet;
import org.ok.communication.PacketManager;
import org.ok.server.client.Client;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.HashMap;

public class Server extends WebSocketServer {

    private final HashMap<WebSocket, Client> clients = new HashMap<>();

    public Server(int port) {
        super(new InetSocketAddress(port));
    }

    public Client getClient(String username) {
        for(Client client : clients.values()) {
            if(client.getUser().getUsername().equals(username)) {
                return client;
            }
        }
        return null;
    }

    @Override
    public void onOpen(WebSocket webSocket, ClientHandshake clientHandshake) {
        if(!clients.containsKey(webSocket)) clients.put(webSocket, new Client());
        clients.get(webSocket).connect(webSocket);
    }

    @Override
    public void onClose(WebSocket webSocket, int i, String s, boolean b) {
        clients.remove(webSocket).disconnect();
    }

    @Override
    public void onMessage(WebSocket webSocket, String s) {
    }

    @Override
    public void onMessage(WebSocket conn, ByteBuffer message) {
        System.out.println("recieved packet from sender");

        Client client = clients.get(conn);

        PacketManager.getInstance().handle(message.array(), client, this);
    }

    @Override
    public void onError(WebSocket webSocket, Exception e) {
        System.out.println("ERROR: " + e);
    }

    @Override
    public void onStart() {
        System.out.println("Server has started!");
    }
}
