package org.ok.protocols;

public class CaesarCipher {

    private char key;

    public CaesarCipher(char key) {
        this.key = (char) (key - 'A');
    }

    public String encrypt(String message) {
        char[] plaintext = message.toLowerCase().toCharArray();
        char[] ciphertext = new char[message.length()];

        for(int i = 0; i < plaintext.length; i++) {
            if('a' <= plaintext[i] && plaintext[i] <= 'z') {
                ciphertext[i] = (char) ('A' + (plaintext[i] + key - 'A'));
            } else {
                ciphertext[i] = plaintext[i];
            }
        }

        return String.valueOf(ciphertext);
    }

    public String decrypt(String ctext) {
        char[] plaintext = new char[ctext.length()];
        char[] ciphertext = ctext.toCharArray();


        for(int i = 0; i < ciphertext.length; i++) {
            if('a' <= ciphertext[i] && ciphertext[i] <= 'z') {
                plaintext[i] = (char) (ciphertext[i] - key);
            } else {
                plaintext[i] = ciphertext[i];
            }
        }

        return String.valueOf(plaintext);
    }
}
