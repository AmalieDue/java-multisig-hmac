package dk.hyperdivision.multisig_hmac;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

/**
 * VerifyDerived represents a verification of a signature of data against dynamically
 * derived keys from a master seed.
 *
 * @author Amalie Due Jensen
 */
public class VerifyDerived {

    /**
     * Verifies a signature of data against dynamically derived keys from a master seed
     *
     * @param MasterSeed - master seed in bytes of length KEYBYTES which the keys are derived from
     * @param Signature - combined signature
     * @param data - data which has been signed
     * @param Threshold - minimum number of used keys
     * @param Algorithm - algorithm used for HMAC
     * @param KEYBYTES  length of keys
     * @param BYTES - length of signature
     * @return verification of the signature (true/false)
     * @throws InvalidKeyException - if the given key is inappropriate for initializing this HMAC
     * @throws NoSuchAlgorithmException - if the specified algorithm is not available
     */
    public static boolean verifyderived(byte[] MasterSeed, Combine Signature, byte[] data, int Threshold, String Algorithm, int KEYBYTES, int BYTES) throws InvalidKeyException, NoSuchAlgorithmException {
        assert MasterSeed.length == KEYBYTES : "MasterSeed must be KEYBYTES long";
        assert Signature.sig.length == BYTES: "Signature must be BYTES long";
        assert Threshold > 0 : "Threshold must be at least 1";

        int BitField = Signature.bitfield;
        int nKeys = Verify.PopCount(BitField);

        if(nKeys < Threshold) {
            return false;
        }

        List<Integer> UsedKeys = Verify.keyIndexes(BitField);
        byte[] Sig = Signature.sig;

        for (Integer usedKey : UsedKeys) {
            DeriveKey Key = new DeriveKey(MasterSeed, usedKey, Algorithm);
            Sign KeySig = new Sign(Key, data, Algorithm);
            Sig = Combine.xorBytes(Sig, KeySig.sign, BYTES);
            BitField ^= KeySig.index;
        }

        return (BitField == 0 && Arrays.equals(Sig, new byte[BYTES]));
    }
}