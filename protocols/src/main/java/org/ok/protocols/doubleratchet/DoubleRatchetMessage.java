package org.ok.protocols.doubleratchet;

import org.ok.protocols.Block;

public class DoubleRatchetMessage {
    Block data;
    DoubleRatchetMessageHeader header;

    public DoubleRatchetMessage(Block data, DoubleRatchetMessageHeader header) {
        this.data = data;
        this.header = header;
    }
}
