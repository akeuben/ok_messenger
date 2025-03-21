package org.ok.app;

import org.java_websocket.client.WebSocketClient;
import org.java_websocket.handshake.ServerHandshake;
import org.ok.communication.PacketManager;

import java.net.URI;
import java.nio.ByteBuffer;
import java.util.ArrayList;

public class Client extends WebSocketClient {

    public Client(URI serverUri) {
        super(serverUri);
    }

    @Override
    public void onOpen(ServerHandshake serverHandshake) {
        System.out.println("Connection opened to server!");
    }

    @Override
    public void onMessage(String s) {
    }

    @Override
    public void onMessage(ByteBuffer bytes) {
        PacketManager.getInstance().handle(bytes.array(), null, this);
    }

    @Override
    public void onClose(int i, String s, boolean b) {
        System.out.println("Closed connection to server");
    }

    @Override
    public void onError(Exception e) {
        System.out.println("Error: " + e);
        App.exit();
    }
}
