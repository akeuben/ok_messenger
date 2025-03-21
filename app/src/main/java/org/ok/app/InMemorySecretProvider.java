package org.ok.app;

import org.h2.mvstore.MVMap;
import org.ok.protocols.Block;
import org.ok.protocols.diffiehellman.DiffieHellman;
import org.ok.protocols.x3dh.X3DHKeyPair;
import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.curve25519.Curve25519KeyPair;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

public class InMemorySecretProvider implements SecretProvider {
    private static final Curve25519 curve = Curve25519.getInstance(Curve25519.BEST);

    private static final Map<String,KeyPair> dhKeyPairs = new HashMap<>();
    private static final Map<String, X3DHKeyPair> x3dhKeyPairs = new HashMap<>();
    private static final Map<String, X3DHKeyPair> signedPrekey = new HashMap<>();

    static {
        dhKeyPairs.put("test", DiffieHellman.from("302a300506032b656e0321001fa22ca7700b28e9a7452a9731b566603fc98e239e21f0eb6a65b92f0d95b03b", "302e020100300506032b656e04220420450fa848debe0ffcacb8d8d066bc543f773e1e52fd54a8ef4276df70964f039d"));

        x3dhKeyPairs.put("avery", X3DHKeyPair.from("f4c834f914db1bcf1199ddcf757774f2fd72e74712c29f21864e8a4486dcac3b", "a80b437250cd22b14b2cedaa5682eafe7ba11aba83769b8b18a51210bf922e42"));
        x3dhKeyPairs.put("test", X3DHKeyPair.from("24120b1932d3781b4a420ef9926e32dd2c27fa1c121d49f8a53c854ea5effb53", "d09886f78e387053aa4f336b712f64b231821bbb64ecbbafe70b0bf5c577334f"));
        signedPrekey.put("test", X3DHKeyPair.from("3930deac493e4f06a0e0779124aab1a3e704a115215212cf6c3b52e7a926b953", "b060c24f2a6cb3df00bec195ad0b34396535def7868b1e5bb8a7533b05a1437e"));
    }

    private final String username;

    public InMemorySecretProvider(String username) {
        this.username = username;
        if(!dhKeyPairs.containsKey(username)) {
            try {
                dhKeyPairs.put(username, DiffieHellman.GenerateKeyPair());
            } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
                throw new RuntimeException(e);
            }
        }

        if(!x3dhKeyPairs.containsKey(username)) {
            Curve25519KeyPair kp = curve.generateKeyPair();
            x3dhKeyPairs.put(username, new X3DHKeyPair(kp));
        }

        if(!signedPrekey.containsKey(username)) {
            Curve25519KeyPair kp = curve.generateKeyPair();
            signedPrekey.put(username, new X3DHKeyPair(kp));
        }

    }


    @Override
    public KeyPair getDHKeyPair() {
        return dhKeyPairs.get(username);
    }

    @Override
    public X3DHKeyPair x3DHKeyPair() {
        return x3dhKeyPairs.get(username);
    }

    @Override
    public X3DHKeyPair signedPrekey() {
        return signedPrekey.get(username);
    }
}
