package org.ok.protocols.doubleratchet;

import org.ok.protocols.Block;

import java.nio.ByteBuffer;
import java.security.PublicKey;

public class DoubleRatchetMessageHeader {
    PublicKey pubKey;
    long pn;
    long n;

    public DoubleRatchetMessageHeader(PublicKey key, long pn, long n) {
        this.pubKey = key;
        this.pn = pn;
        this.n = n;
    }

    public Block toBlock(Block associatedData) {
        Block associatedDataLength = new Block(4, ByteBuffer.allocate(Integer.BYTES).putInt(associatedData.getSizeBytes()).array())

        Block pubKeyBlock = new Block(pubKey.getEncoded());
        Block pnBlock = new Block(ByteBuffer.allocate(Long.BYTES).putLong(pn).array());
        Block nBlock = new Block(ByteBuffer.allocate(Long.BYTES).putLong(n).array());

        return Block.concat(associatedDataLength, associatedData, pubKeyBlock, pnBlock, nBlock);
    }
}
