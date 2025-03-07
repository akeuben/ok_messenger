package org.ok.protocols.doubleratchet;

import org.ok.protocols.Block;
import org.ok.protocols.kdf.KDF;
import org.ok.protocols.aes.AEAD;
import org.ok.protocols.aes.AESKey;
import org.ok.protocols.diffiehellman.DiffieHellman;

import java.security.*;
import java.util.HashMap;
import java.util.Map;

public class DoubleRatchet {
    private static final int MAX_SKIP = 100;

    private final KDF kdf = new KDF();

    private AEAD aead = new AEAD();

    private KeyPair DHs;
    private PublicKey DHr;

    private Block RK;

    private Block CKs, CKr;
    long Ns, Nr;

    long PN;

    Map<PublicKey, Map<Long, AESKey>> MKSKIPPED;

    /**
     * Creates a double ratchet for a scheme started by another party
     * 
     * @param SK             The shared secret key
     * @param otherPublicKey The other user's public key
     */
    public DoubleRatchet(Block SK, PublicKey otherPublicKey) {
        try {
            DHs = DiffieHellman.GenerateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
        DHr = otherPublicKey;
        Block[] val = kdf.kdf_rk(SK, new Block(DiffieHellman.Run(DHs, DHr)));
        RK = val[0];
        CKs = val[1];
        CKr = null;
        Ns = 0;
        Nr = 0;
        PN = 0;
        MKSKIPPED = new HashMap<>();

    }

    /**
     * Creates a double ratchet for a scheme started by the current party.
     * 
     * @param SK        The shared secret key
     * @param myKeyPair Your key pair
     */
    public DoubleRatchet(Block SK, KeyPair myKeyPair) {
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
        Block[] res = kdf.kdf_ck(CKs.getData());
        AESKey mk = new AESKey(res[0].getData());
        CKs = res[1];
        DoubleRatchetMessageHeader header = new DoubleRatchetMessageHeader(DHs.getPublic(), PN, Ns);
        Ns += 1;
        return new DoubleRatchetMessage(aead.encrypt(plaintext, mk, AD), header);
    }

    public Block decrypt(DoubleRatchetMessage message, Block AD) {
        Block plaintext = trySkippedMessageKeys(message, AD);
        if (plaintext != null) {
            return plaintext;
        }
        if (message.header.pubKey != DHr) {
            skipMessageKeys(message.header.pn);
            ratchet(message.header);
        }
        skipMessageKeys(message.header.n);
        Block[] res = kdf.kdf_ck(CKr.getData());
        AESKey mk = new AESKey(res[0].getData());
        CKr = res[1];
        Nr += 1;
        return aead.decrypt(message.data, mk, AD);
    }

    private void ratchet(DoubleRatchetMessageHeader header) {
        PN = Ns;
        Ns = 0;
        Nr = 0;
        DHr = header.pubKey;

        Block[] res = kdf.kdf_rk(RK, new Block(DiffieHellman.Run(DHs, DHr)));
        RK = res[0];
        CKr = res[1];
        try {
            DHs = DiffieHellman.GenerateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
        res = kdf.kdf_rk(RK, new Block(DiffieHellman.Run(DHs, DHr)));
        RK = res[0];
        CKs = res[1];
    }

    private void skipMessageKeys(long until) {
        if (Nr + MAX_SKIP < until) {
            throw new RuntimeException("MAX_SKIP exceeded!");
        }
        if (CKr != null) {
            while (Nr < until) {
                Block[] res = kdf.kdf_ck(CKr.getData());
                AESKey mk = new AESKey(res[0].getData());
                CKr = res[1];
                if (!MKSKIPPED.containsKey(DHr)) {
                    MKSKIPPED.put(DHr, new HashMap<>());
                }
                MKSKIPPED.get(DHr).put(Nr, mk);
                Nr += 1;
            }
        }
    }

    private Block trySkippedMessageKeys(DoubleRatchetMessage message, Block AD) {
        if (MKSKIPPED.containsKey(message.header.pubKey)) {
            Map<Long, AESKey> map = MKSKIPPED.get(message.header.pubKey);
            if (map.containsKey(message.header.n)) {
                AESKey mk = map.remove(message.header.n);
                return aead.decrypt(message.data, mk, AD);
            }
        }
        return null;
    }
}
