package dk.hyperdivision.multisig_hmac;

/**
 * Signature represents an instance of an index + signature pair.
 *
 * @author Amalie Due Jensen
 */
public class Signature {
    int index;
    byte[] signature;

    /**
     * Constructs and initializes a new instance of Signature
     *
     * @param index - the index in the instance
     * @param signature - the signature in the instance
     */
    public Signature(int index, byte[] signature) {
        this.index = index;
        this.signature = signature;
    }
}
