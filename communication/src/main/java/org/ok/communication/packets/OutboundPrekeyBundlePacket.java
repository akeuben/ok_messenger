package org.ok.communication.packets;

import org.ok.communication.Packet;
import org.ok.protocols.Block;
import org.ok.protocols.x3dh.PrekeyBundle;

import java.nio.ByteBuffer;

public class OutboundPrekeyBundlePacket extends Packet {
    public PrekeyBundle bundle;

    public OutboundPrekeyBundlePacket() {
        super((byte)0x01, (byte) 0x06);
    }

    public OutboundPrekeyBundlePacket(PrekeyBundle bundle) {
        this();
        this.bundle = bundle;
    }

    public OutboundPrekeyBundlePacket(byte[] data) {
        this();
        ByteBuffer buffer = ByteBuffer.wrap(data);

        Block identityKey = deserializeBlock(buffer);
        Block signedPrekey = deserializeBlock(buffer);
        Block prekeySignature = deserializeBlock(buffer);

        if(buffer.hasRemaining()) {
            Block onetimePrekey = deserializeBlock(buffer);

            bundle = new PrekeyBundle(identityKey, signedPrekey, prekeySignature, onetimePrekey);
        } else {
            bundle = new PrekeyBundle(identityKey, signedPrekey, prekeySignature);
        }
    }

    @Override
    protected byte[] serializeData() {
        byte[] identityKey = serializeBlock(bundle.getIdentityKey());
        byte[] signedPrekey = serializeBlock(bundle.getSignedPrekey());
        byte[] prekeySignature = serializeBlock(bundle.getPrekeySignature());

        Block otp = bundle.getOneTimePrekey();
        byte[] onetimePrekey = new byte[0];
        if(otp != null) {
            onetimePrekey = serializeBlock(bundle.getOneTimePrekey());
        }

        return ByteBuffer.allocate(identityKey.length + signedPrekey.length + prekeySignature.length + onetimePrekey.length)
                .put(identityKey)
                .put(signedPrekey)
                .put(prekeySignature)
                .put(onetimePrekey)
                .array();
    }


}
