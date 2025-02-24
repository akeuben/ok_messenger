/*Joshua Liu
 * This will be the working version of SHA256 that unit tests will run on when it is re-coded
 */

package org.ok.protocols;

import java.util.Arrays;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA256 {
    public SHA256() {

    }

    public byte[] sha256(byte[] data, long outlen) {
        if (data == null || outlen <= 0) {
            return null; // Handle invalid input
        }

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);

            // Trim or pad the output to the requested length
            return Arrays.copyOf(hash, Math.min((int) outlen, hash.length));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not found", e);
        }
    }
}
