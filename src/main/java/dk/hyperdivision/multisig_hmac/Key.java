package dk.hyperdivision.multisig_hmac;

/**
 * Key represents an instance of an index + cryptographically random key pair.
 *
 * @author Amalie Due Jensen
 */
public class Key {
    int index;
    byte[] key;

    /**
     * Constructs and initializes a new instance of Key
     *
     * @param index - the index in the instance
     * @param key - the key in the instance
     */
    public Key(int index, byte[] key) {
        this.index = index;
        this.key = key;
    }
}
