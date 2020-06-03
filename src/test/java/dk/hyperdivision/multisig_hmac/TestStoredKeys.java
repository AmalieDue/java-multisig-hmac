package dk.hyperdivision.multisig_hmac;

import org.junit.jupiter.api.Test;

import java.util.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

public class TestStoredKeys {
    MultisigHMAC m = new MultisigHMAC(MultisigHMAC.Algorithm.HmacSHA256);

    Key k0 = m.generate(0);
    Key k1 = m.generate(1);
    Key k2 = m.generate(2);

    AssertionError exception;

    @Test
    public void SimpleTest() throws InvalidKeyException, NoSuchAlgorithmException {
        assertNotNull(k0.key);
        assertEquals(k0.key.length, m.KEYBYTES);

        // The data-input to the Sign class has 3 equiv classes: Empty, less
        // than block size, larger than block size. These are tested below
        byte[] dataEmpty = "".getBytes();
        byte[] dataShort = "hello world".getBytes();
        String str = "hello world";
        byte[] dataLong = str.repeat(100).getBytes();

        Signature sEmpty = m.sign(k0, dataEmpty);
        Signature sShort = m.sign(k0, dataShort);
        Signature sLong = m.sign(k0, dataLong);
        assertEquals(sEmpty.signature.length, m.BYTES);
        assertEquals(sShort.signature.length, m.BYTES);
        assertEquals(sLong.signature.length, m.BYTES);

        List<Signature> signatures = new ArrayList<>();
        signatures.add(sEmpty);
        Signature combined = m.combine(signatures);
        assertEquals(combined.signature.length, m.getBYTES());
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

        byte[] message = "".getBytes();
        Signature s0 = m.sign(k0, message);
        Signature s2 = m.sign(k2, message);

        List<Signature> signatures = new ArrayList<>();
        signatures.add(s0);
        signatures.add(s2);

        Signature combined = m.combine(signatures);

        // no keys
        List<Key> keys = new ArrayList<>();
        int threshold = 2;

        exception = assertThrows(AssertionError.class, () ->
                m.verify(keys, combined, message, threshold));
        assertEquals("Not enough keys given based on Signature.bitfield", exception.getMessage());

        // missing some keys
        keys.add(k0);
        exception = assertThrows(AssertionError.class, () ->
                m.verify(keys, combined, message, threshold));
        assertEquals("Not enough keys given based on Signature.bitfield", exception.getMessage());

        // too many keys
        keys.add(k1);
        keys.add(k2);
        assertTrue(m.verify(keys, combined, message, threshold)); // (success)

        // keys in random order
        List<Key> keysRandom = new ArrayList<>();
        keysRandom.add(k0);
        keysRandom.add(k2);
        keysRandom.add(k1);
        assertFalse(m.verify(keysRandom, combined, message, threshold));
    }

    @Test
    public void Test_Signature() throws NoSuchAlgorithmException, InvalidKeyException {
        // The following Signature-inputs are tested:
        //  - empty signature
        //  - signature with wrong bitfield
        //  - signature with too many signatures
        //  - signature with too few signatures
        //  - signature with exactly correct signatures

        byte[] message = "".getBytes();
        Signature s0 = m.sign(k0, message);
        Signature s1 = m.sign(k1, message);
        Signature s2 = m.sign(k2, message);

        List<Signature> signatures = new ArrayList<>();
        List<Key> keys = new ArrayList<>();
        signatures.add(s0);
        signatures.add(s2);
        keys.add(k0);
        keys.add(k1);
        keys.add(k2);
        int threshold = 2;

        Signature combined = m.combine(signatures);

        // empty signature
        combined.signature = "".getBytes();

        exception = assertThrows(AssertionError.class, () ->
                m.verify(keys, combined, message, threshold));
        assertEquals("Signature must be BYTES long", exception.getMessage());

        // signature with wrong bitfield
        Signature combined1 = m.combine(signatures);
        combined1.index = 0;
        assertFalse(m.verify(keys, combined1, message, threshold));

        // signature with too many signatures
        List<Signature> signaturesTooMany = new ArrayList<>();
        signaturesTooMany.add(s0);
        signaturesTooMany.add(s1);
        signaturesTooMany.add(s2);

        Signature combined2 = m.combine(signaturesTooMany);
        combined2.index = combined1.index;
        assertFalse(m.verify(keys, combined2, message, threshold));

        // signature with too few signatures
        Signature combined3 = m.combine(signaturesTooMany);
        combined3.signature = combined1.signature;
        assertFalse(m.verify(keys, combined3, message, threshold));
    }

    @Test
    public void testData() throws NoSuchAlgorithmException, InvalidKeyException {
        // The following Data-inputs are tested:
        //  - Same equiv classes as for the Sign method
        //  - Incorrect data (length - 1, length, length + 1, wrong data)

        // same equiv classes as for the sign function
        byte[] dataEmpty = "".getBytes();
        byte[] dataShort = "hello world".getBytes();
        String str = "hello world";
        byte[] dataLong = str.repeat(100).getBytes();

        Signature s0_empty = m.sign(k0, dataEmpty);
        Signature s1_empty = m.sign(k1, dataEmpty);
        Signature s0_short = m.sign(k0, dataShort);
        Signature s1_short = m.sign(k1, dataShort);
        Signature s0_long = m.sign(k0, dataLong);
        Signature s1_long = m.sign(k1, dataLong);

        List<Signature> signaturesEmpty = new ArrayList<>();
        List<Signature> signaturesShort = new ArrayList<>();
        List<Signature> signaturesLong = new ArrayList<>();
        List<Key> keys = new ArrayList<>();
        signaturesEmpty.add(s0_empty);
        signaturesEmpty.add(s1_empty);
        signaturesShort.add(s0_short);
        signaturesShort.add(s1_short);
        signaturesLong.add(s0_long);
        signaturesLong.add(s1_long);
        keys.add(k0);
        keys.add(k1);
        int threshold = 2;

        Signature combinedEmpty = m.combine(signaturesEmpty);
        Signature combinedShort = m.combine(signaturesShort);
        Signature combinedLong = m.combine(signaturesLong);

        assertTrue(m.verify(keys, combinedEmpty, dataEmpty, threshold));
        assertTrue(m.verify(keys, combinedShort, dataShort, threshold));
        assertTrue(m.verify(keys, combinedLong, dataLong, threshold));

        // incorrect data
        byte[] data_wrong1 = "hello worl".getBytes();
        byte[] data_wrong2 = "hello worldd".getBytes();

        assertFalse(m.verify(keys, combinedShort, data_wrong1, threshold));
        assertFalse(m.verify(keys, combinedShort, data_wrong2, threshold));
    }

    @Test
    public void testThreshold() throws NoSuchAlgorithmException, InvalidKeyException {
        // The following Threshold-inputs are tested:
        //  - -1
        //  - 0
        //  - 1
        //  - Keys.length - 1
        //  - Keys.length
        //  - Keys.length + 1
        //  - Some happy path

        byte[] message = "".getBytes();
        Signature s0 = m.sign(k0, message);
        Signature s1 = m.sign(k1, message);
        List<Signature> signatures = new ArrayList<>();
        List<Key> keys = new ArrayList<>();
        signatures.add(s0);
        signatures.add(s1);
        keys.add(k0);
        keys.add(k1);

        Signature combined = m.combine(signatures);

        // threshold = -1
        exception = assertThrows(AssertionError.class, () ->
                m.verify(keys, combined, message, -1));
        assertEquals("Threshold must be at least 1", exception.getMessage());

        // threshold = 0;
        exception = assertThrows(AssertionError.class, () ->
                m.verify(keys, combined, message, 0));
        assertEquals("Threshold must be at least 1", exception.getMessage());

        // threshold = 1;
        assertTrue(m.verify(keys, combined, message, 1)); // (success)

        // threshold = Keys.length - 1
        assertTrue(m.verify(keys, combined, message, keys.size() - 1)); // (success, unless Keys.length = 1)

        // threshold = Keys.length
        assertTrue(m.verify(keys, combined, message, keys.size())); // (success)

        // threshold = Keys.length + 1
        assertFalse(m.verify(keys, combined, message, keys.size() + 1));
    }

    @Test
    public void Test_Success() throws InvalidKeyException, NoSuchAlgorithmException {
        MultisigHMAC m = new MultisigHMAC(MultisigHMAC.Algorithm.HmacSHA256);

        Key k0 = m.generate(0);
        Key k1 = m.generate(1);
        Key k2 = m.generate(2);

        //Key k2 = new Key();
        //k2.index = k0.index;
        //k2.key = k0.key;

        byte[] message = "hello world".getBytes();

        Signature s0 = m.sign(k0, message);
        Signature s1 = m.sign(k1, message);
        Signature s2 = m.sign(k2, message);

        List<Signature> Signatures = new ArrayList<>();
        Signatures.add(s0);
        Signatures.add(s1);
        Signatures.add(s2);

        Signature combined = m.combine(Signatures);

        List<Key> keys = new ArrayList<>();
        keys.add(k0);
        keys.add(k1);
        keys.add(k2);
        int threshold = 2;

        System.out.println(m.verify(keys, combined, message, threshold));

    }
}