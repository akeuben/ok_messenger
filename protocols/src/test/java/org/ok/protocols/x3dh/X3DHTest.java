package org.ok.protocols.x3dh;

import org.junit.jupiter.api.Test;
import org.ok.protocols.Block;
import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.curve25519.Curve25519KeyPair;

import static org.junit.jupiter.api.Assertions.*;

public class X3DHTest {

    private static Curve25519 curve = Curve25519.getInstance(Curve25519.BEST);

    @Test
    public void test() {
        Curve25519KeyPair aliceKeys = curve.generateKeyPair();
        Curve25519KeyPair bobKeys = curve.generateKeyPair();

        for(int i = 0; i < 100; i++) {

            Curve25519KeyPair bobSignedPrekey = curve.generateKeyPair();
            Curve25519KeyPair bobOneTimePrekey = curve.generateKeyPair();

            PrekeyBundle bobPrekeyBundle = X3DH.createPrekeyBundle(bobKeys, bobSignedPrekey, bobOneTimePrekey);

            X3DHResult aliceResult = X3DH.runSend(bobPrekeyBundle, aliceKeys);

            X3DHMessage message = new X3DHMessage(new Block(aliceKeys.getPublicKey()), aliceResult.getEphemeralKey(), 0, null);

            X3DHResult bobResult = X3DH.runReceive(bobKeys, bobSignedPrekey, bobOneTimePrekey, message);

            assertEquals(aliceResult.getSK(), bobResult.getSK());
            assertEquals(aliceResult.getAD(), bobResult.getAD());
        }
    }
}
