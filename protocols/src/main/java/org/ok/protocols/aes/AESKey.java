package org.ok.protocols.aes;

import org.ok.protocols.Key;

public class AESKey extends Key {
    public AESKey(int size) {
        super(size);
    }

    public AESKey(int size, char[] key) {
        super(size, key);
    }

    public AESKey(int size, String key) {
        super(size, key);
    }

    public AESKey derive() {
        return null;
    }
}
