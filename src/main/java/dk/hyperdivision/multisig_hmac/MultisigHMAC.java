package dk.hyperdivision.multisig_hmac;

/**
 * Multisig scheme for HMAC authentication. Java implementation
 * of https://github.com/emilbayes/multisig-hmac.
 *
 * @author Amalie Due Jensen
 * @version 0.1.0
 */
public class MultisigHMAC {
    String PRIMITIVE;
    int KEYBYTES, BYTES;

    /**
     * The implementation supports SHA256, SHA512, and SHA384 for HMAC
     */
    enum Algorithm {
        HmacSHA256,
        HmacSHA512,
        HmacSHA384
    }

    /**
     * Constructs and initializes a new instance of Multisig HMAC
     * and sets the algorithm to be used for subsequent methods.
     *
     * @param Alg - algorithm used for HMAC
     */
    public MultisigHMAC(Algorithm Alg) {
        switch (Alg) {
            case HmacSHA256:
                PRIMITIVE = "HmacSHA256";
                KEYBYTES = 64;
                BYTES = 32;
                break;
            case HmacSHA512:
                PRIMITIVE = "HmacSHA512";
                KEYBYTES = 128;
                BYTES = 64;
                break;
            case HmacSHA384:
                PRIMITIVE = "HmacSHA384";
                KEYBYTES = 128;
                BYTES = 48;
                break;
        }
    }
}