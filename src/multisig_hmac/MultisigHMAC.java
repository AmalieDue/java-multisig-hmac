package multisig_hmac;

import java.util.*;

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

    public static void main(String[] args) throws Exception{
        MultisigHMAC myObj = new MultisigHMAC(Algorithm.HmacSHA256);

        // Example with stored keys
        KeyGen k0 = new KeyGen(0, myObj.KEYBYTES);
        KeyGen k1 = new KeyGen(1, myObj.KEYBYTES);
        KeyGen k2 = new KeyGen(2, myObj.KEYBYTES);

        byte[] Data = "hello world".getBytes();

        List<Sign> Signatures_stored = new ArrayList<>();
        Signatures_stored.add(new Sign(k0, Data, myObj.PRIMITIVE));
        Signatures_stored.add(new Sign(k2, Data, myObj.PRIMITIVE));

        Combine combined_stored = new Combine(Signatures_stored, myObj.BYTES);

        int Threshold = 2;
        List<IndexKey> Keys = new ArrayList<>();
        Keys.add(k0);
        Keys.add(k1);
        Keys.add(k2);

        System.out.println(Verify.verify(Keys, combined_stored, Data, Threshold, myObj.PRIMITIVE, myObj.BYTES));

        // Example with derived keys
        byte[] Seed = DeriveKey.SeedGen(myObj.KEYBYTES);

        DeriveKey K0 = new DeriveKey(Seed, 0, myObj.PRIMITIVE);
        DeriveKey K1 = new DeriveKey(Seed, 1, myObj.PRIMITIVE);
        DeriveKey K2 = new DeriveKey(Seed, 2, myObj.PRIMITIVE);

        // Same data and threshold as in previous example

        List<Sign> Signatures_derived = new ArrayList<>();
        Signatures_derived.add(new Sign(K0, Data, myObj.PRIMITIVE));
        Signatures_derived.add(new Sign(K2, Data, myObj.PRIMITIVE));

        Combine combined_derived = new Combine(Signatures_derived, myObj.BYTES);

        System.out.println(VerifyDerived.verifyderived(Seed, combined_derived, Data, Threshold, myObj.PRIMITIVE, myObj.BYTES));
    }
}
