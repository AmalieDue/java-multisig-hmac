package dk.hyperdivision.multisig_hmac;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Multisig scheme for HMAC authentication. Java implementation
 * of https://github.com/emilbayes/multisig-hmac.
 *
 * In this case, each of the component keys are stored. The class
 * is extended by the class DerivedMultisigHMAC in which a single
 * master key is stored and used to derive keys ad hoc.
 *
 * @author Amalie Due Jensen
 * @version 2.0.0
 */
public class MultisigHMAC {
    protected String PRIMITIVE;
    protected int KEYBYTES;
    protected int BYTES;

    public String getPRIMITIVE() {
        return PRIMITIVE;
    }

    public int getKEYBYTES() {
        return KEYBYTES;
    }

    public int getBYTES() {
        return BYTES;
    }

    /**
     * The implementation supports SHA256, SHA512, and SHA384 for HMAC
     */
    public enum Algorithm {
        HmacSHA256,
        HmacSHA512,
        HmacSHA384
    }

    /**
     * Constructs and initializes a new instance of MultisigHMAC
     * and sets the algorithm to be used for subsequent methods
     *
     * @param alg - algorithm used for HMAC
     */
    public MultisigHMAC(Algorithm alg) {
        switch (alg) {
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

    /**
     * Generates a new cryptographically random key
     *
     * @param index - index of the key
     * @return the key in bytes of length KEYBYTES
     */
    public Key generate(int index) {
        byte[] keyBytes = new byte[KEYBYTES];
        SecureRandom random = new SecureRandom();
        random.nextBytes(keyBytes);

        return new Key(index, keyBytes);
    }

    /**
     * Independently signs message with a key
     *
     * @param key - key which is an instance of Key used for signing
     * @param message - message which should be signed
     * @return sign of data which is an instance of Signature
     * @throws NoSuchAlgorithmException - if the specified algorithm is not available
     * @throws InvalidKeyException - if the given key is inappropriate for initializing this HMAC
     */
    public Signature sign(Key key, byte[] message) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac HMAC = Mac.getInstance(PRIMITIVE);
        SecretKeySpec hmacKey = new SecretKeySpec(key.key, PRIMITIVE);
        HMAC.init(hmacKey);

        return new Signature(1 << key.index, HMAC.doFinal(message));
    }

    /**
     * Constructs and initializes a combined signature
     *
     * Only include each signature once, otherwise it will cancel out.
     * Signatures can be combined in any order.
     *
     * @param signatures - list of signatures which should be combined
     * @return combined signature as an instance of Signature
     */
    public Signature combine(List<Signature> signatures) {
        int indexCurrent = 0;
        byte[] signatureCurrent = new byte[BYTES];

        for (Signature obj: signatures) {
            indexCurrent ^= obj.index;
            signatureCurrent = xorBytes(signatureCurrent, obj.signature);
        }

        return new Signature(indexCurrent, signatureCurrent);
    }

    /**
     * Xor two byte arrays
     *
     * @param a - first byte array
     * @param b - second byte array
     * @return xor'ed byte array
     */
    protected byte[] xorBytes(byte[] a, byte[] b) {
        byte[] c = new byte[BYTES];
        for (int i = 0; i < Math.max(a.length,b.length); i++) {
            c[i] = (byte) (a[i] ^ b[i]);
        }

        return c;
    }

    /**
     * Verifies a signature of message against a list of keys
     *
     * @param keys - a list of all keys
     * @param signatures - combined signature
     * @param message - message which has been signed
     * @param threshold - minimum number of keys that the list "keys" should contain
     * @return verification of the signature (true/false)
     * @throws InvalidKeyException - if the given key is inappropriate for initializing this HMAC
     * @throws NoSuchAlgorithmException - if the specified algorithm is not available
     */
    public boolean verify(List<Key> keys, Signature signatures, byte[] message, int threshold) throws InvalidKeyException, NoSuchAlgorithmException, IllegalArgumentException {
        if (signatures.signature.length != BYTES) throw new IllegalArgumentException("Signature must be BYTES long");
        if (message == null) throw new IllegalArgumentException("message must be bytes");
        if (threshold <= 0) throw new IllegalArgumentException("Threshold must be at least 1");

        int bitField = signatures.index;
        int nKeys = popCount(bitField);
        int highestKey = 32 - leadingZeros(bitField);
        if (keys.size() < nKeys || keys.size() < highestKey) throw new IllegalArgumentException("Not enough keys given based on index of the combined-Signature");

        if (nKeys < threshold) {
            return false;
        }

        List<Integer> usedKeys = keyIndexes(bitField);
        byte[] sig = signatures.signature;

        for (Object usedKey : usedKeys) {
            Key key = keys.get((Integer) usedKey);
            Signature KeySig = sign(key, message);
            sig = xorBytes(sig, KeySig.signature);
            bitField ^= KeySig.index;
        }

        return (bitField == 0 && Arrays.equals(sig,new byte[BYTES]));
    }

    /**
     * Computes the indexes of the keys (indexes of 1-bits)
     *
     * @param bitField - indexes of keys represented as one integer
     * @return indexes of keys in a list
     */
    protected static List<Integer> keyIndexes(int bitField) {
        List<Integer> keys = new ArrayList<>();
        int i = 0;
        while (bitField > 0) {
            if ((bitField & 0x1) == 1) keys.add(i);
            bitField >>= 1;
            i++;
        }

        return keys;
    }

    /**
     * Computes the number of keys (the number of 1-bits)
     *
     * @param bitField - indexes of keys represented as one integer
     * @return number of keys
     */
    protected static int popCount(int bitField) {
        return Integer.bitCount(bitField);
    }

    /**
     * Computes the number of leading zeros
     *
     * @param bitField - indexes of keys represented as one integer
     * @return number of leading zeros
     */
    protected static int leadingZeros(int bitField) {
        int n = 32;
        int c = 16;
        int y;
        while(c != 0) {
            y = bitField >> c;
            if(y != 0) {
                n = n - c;
                bitField = y;
            }
            c = c >> 1;
        }

        return n - bitField;
    }
}