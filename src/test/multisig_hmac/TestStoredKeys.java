package multisig_hmac;

import org.junit.Test;
import java.util.*;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.*;

public class TestStoredKeys {

    @Test
    public void SimpleTest() throws NoSuchAlgorithmException, InvalidKeyException {
        MultisigHMAC m = new MultisigHMAC(MultisigHMAC.Algorithm.HmacSHA256);

        KeyGen k0 = new KeyGen(0, m.KEYBYTES);
        assertEquals(k0.key.length, m.KEYBYTES);

        // The data-input to the Sign class has 3 equiv classes: Empty, less
        // than block size, larger than block size. These are tested below
        byte[] data_empty = "".getBytes();
        byte[] data_short = "hello world".getBytes();

        String str = "hello world";
        StringBuilder data_long_str = new StringBuilder();
        for (int i = 0; i < 100; i++) {
            data_long_str.append(str);
        }
        byte[] data_long = data_long_str.toString().getBytes();

        Sign s_empty = new Sign(k0, data_empty, m.PRIMITIVE);
        Sign s_short = new Sign(k0, data_short, m.PRIMITIVE);
        Sign s_long = new Sign(k0, data_long, m.PRIMITIVE);
        assertEquals(s_empty.sign.length, m.BYTES);
        assertEquals(s_short.sign.length, m.BYTES);
        assertEquals(s_long.sign.length, m.BYTES);

        List<Sign> Signatures = new ArrayList<>();
        Signatures.add(s_empty);
        Combine combined = new Combine(Signatures, m.BYTES);
        assertEquals(combined.sig.length, m.BYTES);
    }

    // The inputs to the Verify method have more equiv classes

    @Test
    public void Test_Keys() throws NoSuchAlgorithmException, InvalidKeyException {
        // The following keys-inputs are tested:
        //  - no keys
        //  - missing some keys
        //  - too many keys
        //  - keys in random order
        //  - keys in right order

        MultisigHMAC m = new MultisigHMAC(MultisigHMAC.Algorithm.HmacSHA256);

        KeyGen k0 = new KeyGen(0, m.KEYBYTES);
        KeyGen k1 = new KeyGen(1, m.KEYBYTES);
        KeyGen k2 = new KeyGen(2, m.KEYBYTES);
        byte[] Data = "".getBytes();
        Sign s0 = new Sign(k0, Data, m.PRIMITIVE);
        Sign s2 = new Sign(k2, Data, m.PRIMITIVE);

        List<Sign> Signatures = new ArrayList<>();
        Signatures.add(s0);
        Signatures.add(s2);

        Combine combined = new Combine(Signatures, m.BYTES);

        // no keys
        List<IndexKey> Keys = new ArrayList<>();
        int Threshold = 2;
        assertTrue (Verify.verify(Keys, combined, Data, Threshold, m.PRIMITIVE, m.BYTES));
        //if (!Verify.verify(Keys, combined, Data, Threshold, m.PRIMITIVE, m.BYTES)) {
        //    throw new AssertionError("Verification not s")
        //}
    }

    @Test
    public void Test_Threshold() throws NoSuchAlgorithmException, InvalidKeyException {
        // The following Threshold-inputs are tested:
        //  - -1
        //  - 0
        //  - 1
        //  - Keys.length - 1
        //  - Keys.length
        //  - Keys.length + 1
        //  - Some happy path

        MultisigHMAC m = new MultisigHMAC(MultisigHMAC.Algorithm.HmacSHA256);

        KeyGen k0 = new KeyGen(0, m.KEYBYTES);
        KeyGen k1 = new KeyGen(1, m.KEYBYTES);
        byte[] Data = "".getBytes();
        Sign s0 = new Sign(k0, Data, m.PRIMITIVE);
        Sign s1 = new Sign(k1, Data, m.PRIMITIVE);
        List<Sign> Signatures = new ArrayList<>();
        List<IndexKey> Keys = new ArrayList<>();
        Signatures.add(s0);
        Signatures.add(s1);
        Keys.add(k0);
        Keys.add(k1);

        Combine combined = new Combine(Signatures, m.BYTES);

        // Threshold = -1
        int Threshold = -1;
        Verify.verify(Keys, combined, Data, Threshold, m.PRIMITIVE, m.BYTES);

    }

}