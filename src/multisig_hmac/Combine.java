package multisig_hmac;

import java.util.List;

/**
 * Combine combines a list of signatures which have all been signed independently into one signature
 *
 * @author Amalie Due Jensen
 */
public class Combine {
    int bitfield;
    byte[] sig;

    /**
     * Constructs and initializes a combined signature.
     *
     * Only include each signature once, otherwise they will cancel out.
     * Signatures can be combined in any order.
     *
     * @param Signatures - list of signatures
     * @param BYTES - length of combined signature
     */
    public Combine(List<Sign> Signatures, int BYTES) {
        int bitfield_current = 0;
        byte[] sig_current = new byte[BYTES];

        for (Sign obj: Signatures) {
            bitfield_current ^= obj.index;
            sig_current = xorBytes(sig_current, obj.sign);
        }

        this.bitfield = bitfield_current;
        this.sig = sig_current;
    }

    /**
     * Xor two byte arrays
     *
     * @param a - first byte array
     * @param b - second byte array
     * @return result of xor'ing a and b
     */
    public static byte[] xorBytes(byte[] a, byte[] b) {
        byte[] c = new byte[32];
        for (int i = 0; i < Math.max(a.length,b.length); i++) {
            c[i] = (byte) (a[i] ^ b[i]);
        }

        return c;
    }
}