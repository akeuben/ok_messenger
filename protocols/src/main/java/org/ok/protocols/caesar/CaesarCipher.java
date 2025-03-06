package org.ok.protocols.caesar;

public class CaesarCipher {

    private byte key;

    public CaesarCipher(byte key) {
        this.key = (byte) (key - 'A');
    }

    public String encrypt(String message) {
        byte[] plaintext = message.toLowerCase().getBytes();
        byte[] ciphertext = new byte[message.length()];

        for(int i = 0; i < plaintext.length; i++) {
            if('a' <= plaintext[i] && plaintext[i] <= 'z') {
                ciphertext[i] = (byte) ('A' + (plaintext[i] + key - 'A'));
            } else {
                ciphertext[i] = plaintext[i];
            }
        }

        return String.valueOf(ciphertext);
    }

    public String decrypt(String ctext) {
        byte[] plaintext = new byte[ctext.length()];
        byte[] ciphertext = ctext.getBytes();


        for(int i = 0; i < ciphertext.length; i++) {
            if('a' <= ciphertext[i] && ciphertext[i] <= 'z') {
                plaintext[i] = (byte) (ciphertext[i] - key);
            } else {
                plaintext[i] = ciphertext[i];
            }
        }

        return String.valueOf(plaintext);
    }
}
