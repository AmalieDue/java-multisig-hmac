package dk.hyperdivision.multisig_hmac;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

/**
 * Multisig scheme for HMAC authentication. Java implementation
 * of https://github.com/emilbayes/multisig-hmac.
 *
 * @author Amalie Due Jensen
 */
public class DerivedMultisigHMAC extends MultisigHMAC {
    /**
     * Constructs and initializes a new instance of Multisig HMAC
     * and sets the algorithm to be used for subsequent methods. In
     * this case, a single master key is stored and used to derive
     * keys ad hoc.
     *
     * @param alg - algorithm used for HMAC
     */
    public DerivedMultisigHMAC(Algorithm alg) {
        super(alg);
    }

    /**
     * Generates a new cryptographically random master key
     *
     * @return master key
     */
    public byte[] generateMasterKey() {
        byte[] masterKey = new byte[KEYBYTES];
        SecureRandom random = new SecureRandom();
        random.nextBytes(masterKey);

        return masterKey;
    }

    /**
     * Derives a new sub key from a master seed
     *
     * Note that index should be counted from 0.
     * The bitfield/index used with the signature has as many bits as the
     * largest index, hence in practice you want to keep the indexes low.
     *
     * Keys are derived using a KDF based on HMAC:
     * b[0...BYTES] = HMAC(Key = masterKey, data = "derived" || U32LE(index) || 0x00)
     * b[BYTES...] = HMAC(Key = masterKey, b[0...BYTES] || 0x01)
     *
     * @param index - index of the key
     * @param masterKey - master key in bytes of length KEYBYTES used to derive keys
     * @return the derived key in bytes of length KEYBYTES
     * @throws InvalidKeyException - if the given key is inappropriate for initializing this HMAC
     * @throws NoSuchAlgorithmException - if the specified algorithm is not available
     */
    public Key generate(int index, byte[] masterKey) throws InvalidKeyException, NoSuchAlgorithmException {
        byte[] dataBytes = "derived".getBytes();
        byte[] indexArray = intToLittleEndian(index);
        byte[] _scratch = ByteBuffer.allocate(dataBytes.length+indexArray.length).put(dataBytes).put(indexArray).array();

        byte[] ZERO = new byte[] {0x00};
        byte[] ONE = new byte[] {0x01};

        Mac HMAC0 = Mac.getInstance(PRIMITIVE);
        SecretKeySpec hmacKey = new SecretKeySpec(masterKey, PRIMITIVE);
        HMAC0.init(hmacKey);
        HMAC0.update(_scratch);
        byte[] h0 = HMAC0.doFinal(ZERO);

        Mac HMAC1 = Mac.getInstance(PRIMITIVE);
        HMAC1.init(hmacKey);
        HMAC1.update(h0);
        byte[] h1 = HMAC1.doFinal(ONE);

        return new Key(index, ByteBuffer.allocate(h0.length+h1.length).put(h0).put(h1).array());
    }

    /**
     * Converts an integer into a little endian byte array
     *
     * @param index - integer which should be converted
     * @return little endian byte array
     */
    protected static byte[] intToLittleEndian(int index) {
        byte[] b = new byte[4];
        b[0] = (byte) (index & 0xFF);
        b[1] = (byte) ((index >> 8) & 0xFF);
        b[2] = (byte) ((index >> 16) & 0xFF);
        b[3] = (byte) ((index >> 24) & 0xFF);
        return b;
    }

    /**
     * Verifies a signature of data against dynamically derived keys from a master key
     *
     * @param masterKey - master key in bytes of length KEYBYTES which the keys are derived from
     * @param signatures - combined signature
     * @param message - message which has been signed
     * @param threshold - minimum number of used keys
     * @return verification of the signature (true/false)
     * @throws NoSuchAlgorithmException - if the specified algorithm is not available
     * @throws InvalidKeyException - if the given key is inappropriate for initializing this HMAC
     */
    public boolean verify(byte[] masterKey, Signature signatures, byte[] message, int threshold) throws NoSuchAlgorithmException, InvalidKeyException, IllegalArgumentException {
        if (masterKey.length != KEYBYTES) throw new IllegalArgumentException("Master key must be KEYBYTES long");
        if (signatures.signature.length != BYTES) throw new IllegalArgumentException("Signature must be BYTES long");
        if (message == null) throw new IllegalArgumentException("message must be bytes");
        if (threshold <= 0) throw new IllegalArgumentException("Threshold must be at least 1");

        int bitField = signatures.index;
        int nKeys = popCount(bitField);

        if(nKeys < threshold) {
            return false;
        }

        List<Integer> usedKeys = keyIndexes(bitField);
        byte[] sig = signatures.signature;

        for (Integer usedKey : usedKeys) {
            Key key = generate(usedKey, masterKey);
            Signature keySig = sign(key, message);
            sig = xorBytes(sig, keySig.signature);
            bitField ^= keySig.index;
        }

        return (bitField == 0 && Arrays.equals(sig, new byte[BYTES]));
    }
}