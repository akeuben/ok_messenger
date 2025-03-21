package org.ok.protocols.x3dh;

import org.ok.protocols.Block;
import org.ok.protocols.diffiehellman.DiffieHellman;
import org.ok.protocols.kdf.HKDF;
import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.curve25519.Curve25519KeyPair;

public class X3DH {
    private static final Block protocolName = new Block("OkMessenger");
    private static final HKDF hkdf = new HKDF();

    private static final Curve25519 curve = Curve25519.getInstance(Curve25519.BEST);

    public static Block signPrekey(byte[] privateKey, byte[] publicKeyToSign) {
        System.out.println("Signing key " + new Block(publicKeyToSign) + " with " + new Block(privateKey));
        System.out.println("Result: " + new Block(curve.calculateSignature(privateKey, publicKeyToSign)));
        System.out.println("Result: " + new Block(curve.calculateSignature(privateKey, publicKeyToSign)));
        return new Block(curve.calculateSignature(privateKey, publicKeyToSign));
    }

    public static PrekeyBundle createPrekeyBundle(X3DHKeyPair keyPair, X3DHKeyPair preKeyPair) {
        Block signedPreKey = new Block(preKeyPair.getPublicKey());
        Block prekeySignature = signPrekey(keyPair.getPrivateKey(), signedPreKey.getData());
        return new PrekeyBundle(new Block(keyPair.getPublicKey()), signedPreKey, prekeySignature);
    }

    public static PrekeyBundle createPrekeyBundle(X3DHKeyPair keyPair, X3DHKeyPair preKeyPair, X3DHKeyPair oneTimeKey) {
        Block signedPreKey = new Block(preKeyPair.getPublicKey());
        Block prekeySignature = signPrekey(keyPair.getPrivateKey(), signedPreKey.getData());
        return new PrekeyBundle(new Block(keyPair.getPublicKey()), signedPreKey, prekeySignature, new Block(oneTimeKey.getPublicKey()));
    }

    public static X3DHResult runSend(PrekeyBundle prekeyBundle, X3DHKeyPair keyPair) {
        X3DHKeyPair ephemeralKey = X3DHKeyPair.from("10c198b305f726707e71c4c93250bba65134aba7d2b586b97e049538d78e4c6f", "68a16f84504c35fa7d2e973a1f6b60d85a0380996f995039d97a063962b8b26e");

        System.out.println("X3DH SEND");
        System.out.println("Bundle id: " + prekeyBundle.getIdentityKey());
        System.out.println("Bundle spk: " + prekeyBundle.getSignedPrekey());
        System.out.println("Bundle spks: " + prekeyBundle.getPrekeySignature());
        System.out.println("Bundle OTP: " + prekeyBundle.getOneTimePrekey());

        if(!curve.verifySignature(
                prekeyBundle.getIdentityKey().getData(),
                prekeyBundle.getSignedPrekey().getData(),
                prekeyBundle.getPrekeySignature().getData()
        )) {
            throw new RuntimeException("Failed to verify prekey signature");
        }

        Block AD = Block.concat(new Block(keyPair.getPublicKey()), prekeyBundle.getIdentityKey());

        if(prekeyBundle.getOneTimePrekey() == null) {
            Block DH1 = new Block(DiffieHellman.Run(keyPair.getPrivateKey(), prekeyBundle.getSignedPrekey().getData()));
            Block DH2 = new Block(DiffieHellman.Run(ephemeralKey.getPrivateKey(), prekeyBundle.getIdentityKey().getData()));
            Block DH3 = new Block(DiffieHellman.Run(ephemeralKey.getPrivateKey(), prekeyBundle.getSignedPrekey().getData()));

            return new X3DHResult(hkdf.hkdf(new Block(32), Block.concat(DH1, DH2, DH3), protocolName, 32), AD, new Block(ephemeralKey.getPublicKey()));
        } else {
            Block DH1 = new Block(DiffieHellman.Run(keyPair.getPrivateKey(), prekeyBundle.getSignedPrekey().getData()));
            Block DH2 = new Block(DiffieHellman.Run(ephemeralKey.getPrivateKey(), prekeyBundle.getIdentityKey().getData()));
            Block DH3 = new Block(DiffieHellman.Run(ephemeralKey.getPrivateKey(), prekeyBundle.getSignedPrekey().getData()));
            Block DH4 = new Block(DiffieHellman.Run(ephemeralKey.getPrivateKey(), prekeyBundle.getOneTimePrekey().getData()));

            return new X3DHResult(hkdf.hkdf(new Block(32), Block.concat(DH1, DH2, DH3, DH4), protocolName, 32), AD, new Block(ephemeralKey.getPublicKey()));
        }
    }

    public static X3DHResult runReceive(X3DHKeyPair identityKey, X3DHKeyPair signedPrekey, X3DHKeyPair oneTimePrekey, X3DHMessage message) {
        System.out.println("X3DH RECEIVE");
        System.out.println("Identity: Pub: " + new Block(identityKey.getPublicKey()) + ", Priv:" + new Block(identityKey.getPrivateKey()));
        System.out.println("Prekey: Pub: " + new Block(signedPrekey.getPublicKey()) + ", Priv:" + new Block(signedPrekey.getPrivateKey()));
        System.out.println("OTP: " + oneTimePrekey);
        System.out.println("Message id:" + message.identityKey);
        System.out.println("Message em:" + message.emphemeralKey);
        System.out.println("Message pki:" + message.prekeyID);
        System.out.println("Message hpk:" + new Block(message.message.getHeader().getPubKey().getEncoded()));
        byte[] ephemeralKey = message.getEmphemeralKey().getData();
        Block AD = Block.concat(message.getIdentityKey(), new Block(identityKey.getPublicKey()));

        if (oneTimePrekey == null) {
            Block DH1 = new Block(DiffieHellman.Run(signedPrekey.getPrivateKey(), message.getIdentityKey().getData())); // DH(IK_A, SPK_B)
            Block DH2 = new Block(DiffieHellman.Run(identityKey.getPrivateKey(), ephemeralKey)); // DH(EK_A, IK_B)
            Block DH3 = new Block(DiffieHellman.Run(signedPrekey.getPrivateKey(), ephemeralKey)); // DH(EK_A, SPK_B)

            return new X3DHResult(hkdf.hkdf(new Block(32), Block.concat(DH1, DH2, DH3), protocolName, 32), AD, new Block(ephemeralKey));
        } else {
            Block DH1 = new Block(DiffieHellman.Run(signedPrekey.getPrivateKey(), message.getIdentityKey().getData())); // DH(IK_A, SPK_B)
            Block DH2 = new Block(DiffieHellman.Run(identityKey.getPrivateKey(), ephemeralKey)); // DH(EK_A, IK_B)
            Block DH3 = new Block(DiffieHellman.Run(signedPrekey.getPrivateKey(), ephemeralKey)); // DH(EK_A, SPK_B)
            Block DH4 = new Block(DiffieHellman.Run(oneTimePrekey.getPrivateKey(), ephemeralKey));  // DH(EK_A, OPK_B)

            return new X3DHResult(hkdf.hkdf(new Block(32), Block.concat(DH1, DH2, DH3, DH4), protocolName, 32), AD, new Block(ephemeralKey));
        }
    }
}
