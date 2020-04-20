package multisig_hmac;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * DeriveKey represents a pair of index + cryptographically random key.
 *
 * Used for the key management method where a single master seed is stored and
 * used to derive keys ad hoc.
 *
 * @author Amalie Due Jensen
 */
public class DeriveKey extends IndexKey {

    /**
     * Constructs and initializes a pair of index + a new cryptographically random key
     *
     * @param MasterSeed - master seed used to derive keys
     * @param index - index of the key
     * @param Algorithm - algorithm used for HMAC
     * @throws InvalidKeyException - if the given key is inappropriate for initializing this HMAC
     * @throws NoSuchAlgorithmException - if the specified algorithm is not available
     */
    public DeriveKey(byte[] MasterSeed, int index, String Algorithm) throws InvalidKeyException, NoSuchAlgorithmException {
        this.index = index;
        this.key = derivekey(MasterSeed, index, Algorithm);
    }

    /**
     * Derives a new sub key from a master seed
     *
     * @param MasterSeed - master seed used to derive keys
     * @param index - index of the key
     * @param Algorithm - algorithm used for HMAC
     * @return the derived key in bytes of length KEYBYTES
     * @throws InvalidKeyException - if the given key is inappropriate for initializing this HMAC
     * @throws NoSuchAlgorithmException - if the specified algorithm is not available
     */
    public static byte[] derivekey(byte[] MasterSeed, int index, String Algorithm) throws InvalidKeyException, NoSuchAlgorithmException {
        byte[] DataBytes = "derived".getBytes();
        byte[] IndexArray = intToLittleEndian(index);
        byte[] _scratch = ByteBuffer.allocate(DataBytes.length+IndexArray.length).put(DataBytes).put(IndexArray).array();

        byte[] ZERO = new byte[] {0x00};
        byte[] ONE = new byte[] {0x01};

        Mac HMAC0 = Mac.getInstance(Algorithm);
        SecretKeySpec Key = new SecretKeySpec(MasterSeed, Algorithm);
        HMAC0.init(Key);
        HMAC0.update(_scratch);
        byte[] h0 = HMAC0.doFinal(ZERO);

        Mac HMAC1 = Mac.getInstance(Algorithm);
        HMAC1.init(Key);
        HMAC1.update(h0);
        byte[] h1 = HMAC1.doFinal(ONE);

        return ByteBuffer.allocate(h0.length+h1.length).put(h0).put(h1).array();
    }

    /**
     * Generates a new cryptographically random master seed
     *
     * @param KEYBYTES - length of the master seed
     * @return master seed
     */
    public static byte[] SeedGen(int KEYBYTES) {
        byte[] SeedGen = new byte[KEYBYTES];
        SecureRandom random = new SecureRandom();
        random.nextBytes(SeedGen);

        return SeedGen;
    }

    /**
     * Converts an integer into a little endian byte array
     *
     * @param index - integer which should be converted
     * @return little endian byte array
     */
    public static byte[] intToLittleEndian(int index) {
        byte[] b = new byte[4];
        b[0] = (byte) (index & 0xFF);
        b[1] = (byte) ((index >> 8) & 0xFF);
        b[2] = (byte) ((index >> 16) & 0xFF);
        b[3] = (byte) ((index >> 24) & 0xFF);
        return b;
    }
}