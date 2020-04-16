package multisig_hmac;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class DeriveKey extends IndexKey {

    public DeriveKey(byte[] MasterSeed, int index, String Algorithm) throws InvalidKeyException, NoSuchAlgorithmException {
        this.index = index;
        this.key = derivekey(MasterSeed, index, Algorithm);
    }

    public static byte[] derivekey(byte[] MasterSeed, int index, String Algorithm) throws NoSuchAlgorithmException, InvalidKeyException {
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

    public static byte[] SeedGen(int KEYBYTES) {
        byte[] SeedGen = new byte[KEYBYTES];
        SecureRandom random = new SecureRandom();
        random.nextBytes(SeedGen);

        return SeedGen;
    }

    public static byte[] intToLittleEndian(int index) {
        byte[] b = new byte[4];
        b[0] = (byte) (index & 0xFF);
        b[1] = (byte) ((index >> 8) & 0xFF);
        b[2] = (byte) ((index >> 16) & 0xFF);
        b[3] = (byte) ((index >> 24) & 0xFF);
        return b;
    }
}