package multisig_hmac;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Verify {
    public static boolean verify(List<IndexKey> Keys, Object[] Signature, byte[] data, int Threshold, String Algorithm, int BYTES) throws InvalidKeyException, NoSuchAlgorithmException {

        int BitField = (int) Signature[0];
        int nKeys = PopCount(BitField);

        if (nKeys < Threshold) {
            return false;
        }

        List<Integer> UsedKeys = keyIndexes(BitField);
        byte[] Sig = (byte[]) Signature[1];

        for (Object obj : UsedKeys) {
            IndexKey Key = Keys.get((Integer) obj);
            Sign KeySig = new Sign(Key, data, Algorithm);
            Sig = multisig_hmac.Combine.xorBytes(Sig, KeySig.sign);
            BitField ^= KeySig.index;
        }

        return (BitField == 0 && Arrays.equals(Sig,new byte[BYTES]));
    }

    public static List<Integer> keyIndexes(int BitField) {
        List<Integer> KeyIndexes = new ArrayList<>();
        int i = 0;
        while (BitField > 0) {
            if ((BitField & 0x1) == 1) KeyIndexes.add(i);
            BitField >>= 1;
            i++;
        }
        return KeyIndexes;
    }

    public static int PopCount(int BitField) {
        return Integer.bitCount(BitField);
    }
}