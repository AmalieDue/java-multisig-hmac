package multisig_hmac;

import java.util.*;

enum Algorithm {
    HmacSHA256,
    HmacSHA512,
    HmacSHA384
}

public class MultisigHMAC {
    String PRIMITIVE;
    int KEYBYTES, BYTES;

    public MultisigHMAC(Algorithm Alg) {

        switch (Alg) {
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
            default:
                PRIMITIVE = "HmacSHA256";
                KEYBYTES = 64;
                BYTES = 32;
        }
    }

    public static void main(String[] args) throws Exception{
        MultisigHMAC myObj = new MultisigHMAC(Algorithm.HmacSHA256);

        // Example with stored keys
        KeyGen k0 = new KeyGen(0, myObj.KEYBYTES);
        //System.out.println("Index: " + k0.IndexKey[0] + " Key: " + Base64.getEncoder().encodeToString((byte[]) k0.IndexKey[1]));
        KeyGen k1 = new KeyGen(1, myObj.KEYBYTES);
        KeyGen k2 = new KeyGen(2, myObj.KEYBYTES);

        byte[] Data = "hello world".getBytes();

        List<Sign> Signatures_stored = new ArrayList<>();
        Signatures_stored.add(new Sign(k0.IndexKey, Data, myObj.PRIMITIVE));
        Signatures_stored.add(new Sign(k2.IndexKey, Data, myObj.PRIMITIVE));

        Object[] out_stored = Combine.combine(Signatures_stored, myObj.BYTES);

        int Threshold = 2;
        List<Object[]> Keys = new ArrayList<>();
        Keys.add(k0.IndexKey);
        Keys.add(k1.IndexKey);
        Keys.add(k2.IndexKey);

        System.out.println(Verify.verify(Keys, out_stored, Data, Threshold, myObj.PRIMITIVE, myObj.BYTES));

        // Example with derived keys
        byte[] Seed = DeriveKey.SeedGen(myObj.KEYBYTES);

        DeriveKey K0 = new DeriveKey(Seed, 0, myObj.PRIMITIVE);
        DeriveKey K1 = new DeriveKey(Seed, 1, myObj.PRIMITIVE);
        DeriveKey K2 = new DeriveKey(Seed, 2, myObj.PRIMITIVE);

        // Same data as in previous example

        List<Sign> Signatures_derived = new ArrayList<>();
        Signatures_derived.add(new Sign(K0.IndexKey, Data, myObj.PRIMITIVE));
        Signatures_derived.add(new Sign(K2.IndexKey, Data, myObj.PRIMITIVE));

        Object[] out_derived = Combine.combine(Signatures_derived, myObj.BYTES);

        // Same threshold as in previous example

        System.out.println(VerifyDerived.verifyderived(Seed, out_derived, Data, Threshold, myObj.PRIMITIVE, myObj.BYTES));
    }
}
