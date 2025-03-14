package org.ok.server;

import org.java_websocket.WebSocket;
import org.java_websocket.handshake.ClientHandshake;
import org.java_websocket.server.WebSocketServer;
import org.ok.communication.Packet;
import org.ok.communication.PacketManager;
import org.ok.server.client.Client;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

public class Server extends WebSocketServer {

    public Server(int port) {
        super(new InetSocketAddress(port));
    }

    @Override
    public void onOpen(WebSocket webSocket, ClientHandshake clientHandshake) {
        System.out.println("Server has received connection: " + webSocket.getRemoteSocketAddress());
        webSocket.send("Hello client!");
    }

    @Override
    public void onClose(WebSocket webSocket, int i, String s, boolean b) {
        System.out.println("Server has received disconnection: " + webSocket.getRemoteSocketAddress());
    }

    @Override
    public void onMessage(WebSocket webSocket, String s) {
        System.out.println("Server has received message " + s + " from " + webSocket.getRemoteSocketAddress());
        webSocket.send("Pong! " + s);
    }

    @Override
    public void onMessage(WebSocket conn, ByteBuffer message) {
        System.out.println("recieved packet from sender");
        Client client = new Client(conn);

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
