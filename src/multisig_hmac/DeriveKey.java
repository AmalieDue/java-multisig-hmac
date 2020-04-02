package multisig_hmac;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class DeriveKey {

    Object[] IndexKey = new Object[2];

    public DeriveKey(byte[] MasterSeed, int index, String Algorithm) throws InvalidKeyException, NoSuchAlgorithmException {

        IndexKey[0] = index;
        IndexKey[1] = derivekey(MasterSeed, index, Algorithm);
    }

    public static byte[] derivekey(byte[] MasterSeed, int index, String Algorithm) throws NoSuchAlgorithmException, InvalidKeyException {

        String Data = "derived";
        byte[] DataBytes = Data.getBytes();
        byte[] IndexArray = intToLittleEndian(index);
        byte[] _scratch = new byte[DataBytes.length + IndexArray.length];
        System.arraycopy(DataBytes,0,_scratch,0,DataBytes.length);
        System.arraycopy(IndexArray,0,_scratch,DataBytes.length,IndexArray.length);

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

        byte[] FinalKey = new byte[h0.length + h1.length];
        System.arraycopy(h0,0,FinalKey,0,h0.length);
        System.arraycopy(h1,0,FinalKey,h0.length,h1.length);

        return FinalKey;
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