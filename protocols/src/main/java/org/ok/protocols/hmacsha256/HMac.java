package org.ok.protocols.hmacsha256;

import org.ok.protocols.Block;

public interface HMac {
    Block encode(Block value, Block secretKey);
    boolean verify(Block hMac, Block publicKey);
}
