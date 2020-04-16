package multisig_hmac;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

public class VerifyDerived {

    public static boolean verifyderived(byte[] MasterSeed, Object[] Signature, byte[] data, int Threshold, String Algorithm, int BYTES) throws InvalidKeyException, NoSuchAlgorithmException {
        int BitField = (int) Signature[0];
        int nKeys = Verify.PopCount(BitField);

        if(nKeys < Threshold) {
            return false;
        }

        List<Integer> UsedKeys = Verify.keyIndexes(BitField);
        byte[] Sig = (byte[]) Signature[1];

        for (Integer usedKey : UsedKeys) {
            DeriveKey Key = new DeriveKey(MasterSeed, usedKey, Algorithm);
            Sign KeySig = new Sign(Key, data, Algorithm);
            Sig = Combine.xorBytes(Sig, (byte[]) KeySig.IndexSign[1]);
            BitField ^= (int) KeySig.IndexSign[0];
        }

        return (BitField == 0 && Arrays.equals(Sig, new byte[BYTES]));
    }
}