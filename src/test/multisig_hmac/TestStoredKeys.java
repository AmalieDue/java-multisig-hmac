package multisig_hmac;

import org.junit.Test;
import java.util.*;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.*;

public class TestStoredKeys {
    MultisigHMAC m = new MultisigHMAC(MultisigHMAC.Algorithm.HmacSHA256);
    KeyGen k0 = new KeyGen(0, m.KEYBYTES);
    KeyGen k1 = new KeyGen(1, m.KEYBYTES);
    KeyGen k2 = new KeyGen(2, m.KEYBYTES);

    @Test
    public void SimpleTest() throws NoSuchAlgorithmException, InvalidKeyException {
        assertNotNull(k0.key);
        assertEquals(k0.key.length, m.KEYBYTES);

        // The data-input to the Sign class has 3 equiv classes: Empty, less
        // than block size, larger than block size. These are tested below
        byte[] data_empty = "".getBytes();
        byte[] data_short = "hello world".getBytes();
        String str = "hello world";
        byte[] data_long = str.repeat(100).getBytes();

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
        try {
            Verify.verify(Keys, combined, Data, Threshold, m.PRIMITIVE, m.BYTES);
        } catch (AssertionError ignored) {
        }

        // missing some keys
        Keys.add(k0);
        try {
            Verify.verify(Keys, combined, Data, Threshold, m.PRIMITIVE, m.BYTES);
        } catch (AssertionError ignored) {
        }

        // too many keys
        Keys.add(k1);
        Keys.add(k2);
        assertTrue(Verify.verify(Keys, combined, Data, Threshold, m.PRIMITIVE, m.BYTES)); // (success)

        // keys in random order
        List<IndexKey> KeysRandom = new ArrayList<>();
        KeysRandom.add(k0);
        KeysRandom.add(k2);
        KeysRandom.add(k1);
        assertFalse(Verify.verify(KeysRandom, combined, Data, Threshold, m.PRIMITIVE, m.BYTES));
    }

    @Test
    public void Test_Signature() throws NoSuchAlgorithmException, InvalidKeyException {
        // The following Signature-inputs are tested:
        //  - empty signature
        //  - signature with wrong bitfield
        //  - signature with too many signatures
        //  - signature with too few signatures
        //  - signature with exactly correct signatures

        byte[] Data = "".getBytes();
        Sign s0 = new Sign(k0, Data, m.PRIMITIVE);
        Sign s1 = new Sign(k1, Data, m.PRIMITIVE);
        Sign s2 = new Sign(k2, Data, m.PRIMITIVE);

        List<Sign> Signatures = new ArrayList<>();
        List<IndexKey> Keys = new ArrayList<>();
        Signatures.add(s0);
        Signatures.add(s2);
        Keys.add(k0);
        Keys.add(k1);
        Keys.add(k2);
        int Threshold = 2;

        Combine combined = new Combine(Signatures, m.BYTES);

        // empty signature
        combined.sig = "".getBytes();
        try {
            Verify.verify(Keys, combined, Data, Threshold, m.PRIMITIVE, m.BYTES);
        } catch (AssertionError ignored){
        }

        // signature with wrong bitfield
        Combine combined1 = new Combine(Signatures, m.BYTES);
        combined1.bitfield = 0;
        assertFalse(Verify.verify(Keys, combined1, Data, Threshold, m.PRIMITIVE, m.BYTES));

        // signature with too many signatures
        List<Sign> SignaturesTooMany = new ArrayList<>();
        SignaturesTooMany.add(s0);
        SignaturesTooMany.add(s1);
        SignaturesTooMany.add(s2);

        Combine combined2 = new Combine(SignaturesTooMany, m.BYTES);
        combined2.bitfield = combined1.bitfield;
        assertFalse(Verify.verify(Keys, combined2, Data, Threshold, m.PRIMITIVE, m.BYTES));

        // signature with too few signatures
        Combine combined3 = new Combine(SignaturesTooMany, m.BYTES);
        combined3.sig = combined1.sig;
        assertFalse(Verify.verify(Keys, combined3, Data, Threshold, m.PRIMITIVE, m.BYTES));
    }

    @Test
    public void Test_Data() throws NoSuchAlgorithmException, InvalidKeyException {
        // The following Data-inputs are tested:
        //  - Same equiv classes as for the Sign method
        //  - Incorrect data (length - 1, length, length + 1, wrong data)

        // same equiv classes as for the sign function
        byte[] data_empty = "".getBytes();
        byte[] data_short = "hello world".getBytes();
        String str = "hello world";
        byte[] data_long = str.repeat(100).getBytes();

        Sign s0_empty = new Sign(k0, data_empty, m.PRIMITIVE);
        Sign s1_empty = new Sign(k1, data_empty, m.PRIMITIVE);
        Sign s0_short = new Sign(k0, data_short, m.PRIMITIVE);
        Sign s1_short = new Sign(k1, data_short, m.PRIMITIVE);
        Sign s0_long = new Sign(k0, data_long, m.PRIMITIVE);
        Sign s1_long = new Sign(k1, data_long, m.PRIMITIVE);

        List<Sign> Signatures_empty = new ArrayList<>();
        List<Sign> Signatures_short = new ArrayList<>();
        List<Sign> Signatures_long = new ArrayList<>();
        List<IndexKey> Keys = new ArrayList<>();
        Signatures_empty.add(s0_empty);
        Signatures_empty.add(s1_empty);
        Signatures_short.add(s0_short);
        Signatures_short.add(s1_short);
        Signatures_long.add(s0_long);
        Signatures_long.add(s1_long);
        Keys.add(k0);
        Keys.add(k1);
        int Threshold = 2;

        Combine combined_empty = new Combine(Signatures_empty, m.BYTES);
        Combine combined_short = new Combine(Signatures_short, m.BYTES);
        Combine combined_long = new Combine(Signatures_long, m.BYTES);

        assertTrue(Verify.verify(Keys, combined_empty, data_empty, Threshold, m.PRIMITIVE, m.BYTES));
        assertTrue(Verify.verify(Keys, combined_short, data_short, Threshold, m.PRIMITIVE, m.BYTES));
        assertTrue(Verify.verify(Keys, combined_long, data_long, Threshold, m.PRIMITIVE, m.BYTES));

        // incorrect data
        byte[] data_wrong1 = "hello worl".getBytes();
        byte[] data_wrong2 = "hello worldd".getBytes();

        assertFalse(Verify.verify(Keys, combined_short, data_wrong1, Threshold, m.PRIMITIVE, m.BYTES));
        assertFalse(Verify.verify(Keys, combined_short, data_wrong2, Threshold, m.PRIMITIVE, m.BYTES));
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

        // threshold = -1
        int Threshold = -1;
        try {
            Verify.verify(Keys, combined, Data, Threshold, m.PRIMITIVE, m.BYTES);
        } catch (AssertionError ignored){
        }

        // threshold = 0;
        Threshold = 0;
        try {
            Verify.verify(Keys, combined, Data, Threshold, m.PRIMITIVE, m.BYTES);
        } catch (AssertionError ignored){
        }

        // threshold = 1;
        Threshold = 1;
        assertTrue(Verify.verify(Keys, combined, Data, Threshold, m.PRIMITIVE, m.BYTES)); // (success)

        // threshold = Keys.length - 1
        Threshold = Keys.size() - 1;
        assertTrue(Verify.verify(Keys, combined, Data, Threshold, m.PRIMITIVE, m.BYTES)); // (success, unless Keys.length = 1)

        // threshold = Keys.length
        Threshold = Keys.size();
        assertTrue(Verify.verify(Keys, combined, Data, Threshold, m.PRIMITIVE, m.BYTES)); // (success)

        // threshold = Keys.length + 1
        Threshold = Keys.size() + 1;
        assertFalse(Verify.verify(Keys, combined, Data, Threshold, m.PRIMITIVE, m.BYTES));
    }

    @Test
    public void Test_Success() throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] Data = "hello world".getBytes();
        Sign s0 = new Sign(k0, Data, m.PRIMITIVE);
        Sign s2 = new Sign(k2, Data, m.PRIMITIVE);

        List<Sign> Signatures = new ArrayList<>();
        List<IndexKey> Keys = new ArrayList<>();
        Signatures.add(s0);
        Signatures.add(s2);
        Keys.add(k0);
        Keys.add(k1);
        Keys.add(k2);
        int Threshold = 2;

        Combine combined = new Combine(Signatures, m.BYTES);

        assertTrue(Verify.verify(Keys, combined, Data, Threshold, m.PRIMITIVE, m.BYTES));
    }

}