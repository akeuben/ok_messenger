package org.ok.protocols;

public abstract class Key extends Block {
    public Key(int size) {
        super(size);
    }

    public Key(int size, char[] key) {
        super(size, key);
    }

    public Key(int size, String key) {
        super(size, key);
    }
}
