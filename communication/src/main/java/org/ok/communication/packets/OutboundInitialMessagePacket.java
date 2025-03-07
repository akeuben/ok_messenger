package org.ok.communication.packets;

import org.ok.communication.Packet;
import org.ok.protocols.Block;
import org.ok.protocols.diffiehellman.DiffieHellman;
import org.ok.protocols.x3dh.X3DHMessage;

import java.nio.ByteBuffer;
import java.security.PublicKey;

public class OutboundInitialMessagePacket extends Packet {

    public final Block identityKey;
    public final Block emphemeralKey;
    public final long prekeyID;
    public final Block data;
    public final PublicKey pubKey;
    public final long pn;
    public final long n;


    public OutboundInitialMessagePacket(X3DHMessage message) {
        super((byte) 0x01, (byte) 0x03);

        identityKey = message.getIdentityKey();
        emphemeralKey = message.getEmphemeralKey();
        prekeyID = message.getPrekeyID();
        data = message.getMessage().getData();
        pubKey = message.getMessage().getHeader().getPubKey();
        pn = message.getMessage().getHeader().getPn();
        n = message.getMessage().getHeader().getN();
    }

    public OutboundInitialMessagePacket(byte[] rawPacket) {
        super((byte) 0x01, (byte) 0x03);

        ByteBuffer buffer = ByteBuffer.wrap(rawPacket);
        int identityKeyLength = buffer.getInt();
        byte[] identityKey = new byte[identityKeyLength];
        buffer.get(identityKey, 0, identityKeyLength);
        this.identityKey = new Block(identityKey);

        int emphemeralKeyLength = buffer.getInt();
        byte[] emphemeralKey = new byte[emphemeralKeyLength];
        buffer.get(emphemeralKey, 0, emphemeralKeyLength);
        this.emphemeralKey = new Block(emphemeralKey);

        this.prekeyID = buffer.getLong();

        int dataLength = buffer.getInt();
        byte[] data = new byte[dataLength];
        buffer.get(data, 0, dataLength);
        this.data = new Block(data);

        int pubKeyLength = buffer.getInt();
        byte[] pubKey = new byte[pubKeyLength];
        buffer.get(pubKey, 0, pubKeyLength);
        this.pubKey = DiffieHellman.decodePublicKey(pubKey);

        this.pn = buffer.getLong();
        this.n = buffer.getLong();
    }

    @Override
    protected byte[] serializeData() {
        int identityKeyLength = identityKey.getSizeBytes();
        byte[] identityKey = this.identityKey.getData();

        int emphemeralKeyLength = emphemeralKey.getSizeBytes();
        byte[] emphemeralKey = this.emphemeralKey.getData();

        int dataLength = data.getSizeBytes();
        byte[] data = this.data.getData();

        byte[] pubKey = this.pubKey.getEncoded();
        int pubKeyLength = pubKey.length;

        return ByteBuffer.allocate(Integer.BYTES + identityKeyLength +
                        Integer.BYTES + emphemeralKeyLength +
                        Long.BYTES +
                        Integer.BYTES + dataLength +
                        Integer.BYTES + pubKeyLength +
                        Long.BYTES +
                        Long.BYTES)
                .putInt(identityKeyLength)
                .put(identityKey)
                .putInt(emphemeralKeyLength)
                .put(emphemeralKey)
                .putLong(prekeyID)
                .putInt(dataLength)
                .put(data)
                .putInt(pubKeyLength)
                .put(pubKey)
                .putLong(pn)
                .putLong(n)
                .array();
    }
}
