package dk.hyperdivision.multisig_hmac;

import java.security.SecureRandom;

/**
 * KeyGen represents a pair of index + cryptographically random key.
 *
 * Used for the key management method where each component key is stored.
 *
 * @author Amalie Due Jensen
 */
public class KeyGen extends IndexKey {

    /**
     * Constructs and initializes a pair of index + a new cryptographically random key.
     * Note that index should be counted from 0.
     *
     * @param index - index of the key
     * @param KEYBYTES - length of the key
     */
    public KeyGen(int index, int KEYBYTES) {
        this.index = index;
        this.key = keygen(KEYBYTES);
    }

    /**
     * Generates a new cryptographically random key
     *
     * @param KEYBYTES - length of the key
     * @return key in bytes of length KEYBYTES
     */
    public static byte[] keygen(int KEYBYTES) {
        byte[] Key = new byte[KEYBYTES];
        SecureRandom random = new SecureRandom();
        random.nextBytes(Key);

        return Key;
    }
}
