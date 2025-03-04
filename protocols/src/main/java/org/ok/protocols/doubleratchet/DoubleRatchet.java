package org.ok.protocols.doubleratchet;

import org.ok.protocols.Block;
import org.ok.protocols.aes.AEAD_AESCTR_HMAC;
import org.ok.protocols.diffiehellman.DiffieHellman;

import java.security.*;
import java.util.HashMap;
import java.util.Map;

public class DoubleRatchet {
    private static final int MAX_SKIP = 100;

    private AEAD_AESCTR_HMAC aes = new AEAD_AESCTR_HMAC();

    private KeyPair DHs;
    private PublicKey DHr;

    private Key RK;

    Key CKs, CKr;
    long Ns, Nr;

    long PN;

    Map<PublicKey, Map<Long, Key>> MKSKIPPED;

    /**
     * Creates a double ratchet for a scheme started by another party
     * @param SK The shared secret key
     * @param otherPublicKey The other user's public key
     */
    public DoubleRatchet(Key SK, PublicKey otherPublicKey) {
        try {
            DHs = DiffieHellman.GenerateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
        RK, CKs = KDF_RK(SK, DH(DHs, DHr));
        DHr = otherPublicKey;
        CKr = null;
        Ns = 0;
        Nr = 0;
        PN = 0;
        MKSKIPPED = new HashMap<>();

    }

    /**
     * Creates a double ratchet for a scheme started by the current party.
     * @param SK The shared secret key
     * @param myKeyPair Your key pair
     */
    public DoubleRatchet(Key SK, KeyPair myKeyPair) {
        DHs = myKeyPair;
        DHr = null;
        RK = SK;
        CKs = null;
        CKr = null;
        Ns = 0;
        Nr = 0;
        PN = 0;
        MKSKIPPED = new HashMap<>();
    }

    public DoubleRatchetMessage encrypt(Block plaintext, Block AD) {
        CKs, mk = KDF_CK(CKs);
        DoubleRatchetMessageHeader header = new DoubleRatchetMessageHeader(DHs.getPublic(), PN, Ns);
        Ns += 1;
        return new DoubleRatchetMessage(header, aes.encrypt(mk, plaintext, header.toBlock(AD)));
    }

    public Block decrypt(DoubleRatchetMessage message, Block AD) {
        Block plaintext = trySkippedMessageKeys(message, AD);
        if(plaintext != null) {
            return plaintext;
        }
        if(message.header.pubKey != DHr) {
            skipMessageKeys(message.header.pn);
            ratchet(message.header);
        }
        skipMessageKeys(message.header.n);
        CKr, mk = KDF_CK(CKr);
        Nr += 1;
        return aes.decrypt(mk, message.data, message.header.toBlock(AD));
    }

    private void ratchet(DoubleRatchetMessageHeader header) {
        PN = Ns;
        Ns = 0;
        Nr = 0;
        DHr = header.pubKey;
        RK, CKr = KDF_RK(RK, DH(DHs, DHr));
        try {
            DHs = DiffieHellman.GenerateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
        RK, CKs = KDF_RK(RK, DH(DHs, DHr));
    }

    private void skipMessageKeys(long until) {
        if(Nr + MAX_SKIP < until) {
            throw new RuntimeException("MAX_SKIP exceeded!");
        }
        if(CKr != null) {
            while(Nr < until) {
                CKr, mk = KDF_CK(CKr);
                if(!MKSKIPPED.containsKey(DHr)) {
                    MKSKIPPED.put(DHr, new HashMap<>());
                }
                MKSKIPPED.get(DHr).put(Nr, mk);
                Nr += 1;
            }
        }
    }

    private Block trySkippedMessageKeys(DoubleRatchetMessage message, Block AD) {
        if(MKSKIPPED.containsKey(message.header.pubKey)) {
            Map<Long, Key> map = MKSKIPPED.get(message.header.pubKey);
            if(map.containsKey(message.header.n)) {
                Key mk = map.remove(message.header.n);
                return aes.decrypt(mk.getEncoded(), message.data, message.header.toBlock(AD));
            }
        }
        return null;
    }
}
