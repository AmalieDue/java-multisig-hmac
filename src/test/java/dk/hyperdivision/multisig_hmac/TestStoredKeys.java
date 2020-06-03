package dk.hyperdivision.multisig_hmac;

import org.junit.jupiter.api.Test;
import java.util.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

public class TestStoredKeys {
    MultisigHMAC m = new MultisigHMAC(MultisigHMAC.Algorithm.HmacSHA256);

    Key k0 = m.generate(0);
    Key k1 = m.generate(1);
    Key k2 = m.generate(2);

    @Test
    public void simpleTest() throws InvalidKeyException, NoSuchAlgorithmException {
        assertNotNull(k0.key);
        assertEquals(k0.key.length, m.KEYBYTES);

        // The message-input to the MultisigHMAC.sign method has 3 equiv classes: Empty, less
        // than block size, larger than block size. These are tested below
        byte[] messageEmpty = "".getBytes();
        byte[] messageShort = "hello world".getBytes();
        String str = "hello world";
        byte[] messageLong = str.repeat(100).getBytes();

        Signature sEmpty = m.sign(k0, messageEmpty);
        Signature sShort = m.sign(k0, messageShort);
        Signature sLong = m.sign(k0, messageLong);
        assertEquals(sEmpty.signature.length, m.BYTES);
        assertEquals(sShort.signature.length, m.BYTES);
        assertEquals(sLong.signature.length, m.BYTES);

        List<Signature> signatures = new ArrayList<>();
        signatures.add(sEmpty);
        Signature combined = m.combine(signatures);
        assertEquals(combined.signature.length, m.getBYTES());
    }

    // The inputs to the MultisigHMAC.verify method have more equiv classes

    @Test
    public void testKeys() throws NoSuchAlgorithmException, InvalidKeyException {
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

        try {
            m.verify(keys, combined, message, threshold);
        } catch (IllegalArgumentException expected) {
            assert(expected.getMessage()).contains("Not enough keys given based on index of the combined-Signature");
        }

        // missing some keys
        keys.add(k0);
        try {
            m.verify(keys, combined, message, threshold);
        } catch (IllegalArgumentException expected) {
            assert(expected.getMessage()).contains("Not enough keys given based on index of the combined-Signature");
        }

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
    public void testSignature() throws NoSuchAlgorithmException, InvalidKeyException {
        // The following signature-inputs are tested:
        //  - empty signature
        //  - signature with wrong index
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

        try {
            m.verify(keys, combined, message, threshold);
        } catch (IllegalArgumentException expected) {
            assert(expected.getMessage()).contains("Signature must be BYTES long");
        }

        // signature with wrong index
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
    public void testMessage() throws NoSuchAlgorithmException, InvalidKeyException {
        // The following message-inputs are tested:
        //  - Same equiv classes as for the MultisigHMAC.sign method
        //  - Incorrect message (length - 1, length, length + 1, wrong message)

        // same equiv classes as for the MultisigHMAC.sign method
        byte[] messageEmpty = "".getBytes();
        byte[] messageShort = "hello world".getBytes();
        String str = "hello world";
        byte[] messageLong = str.repeat(100).getBytes();

        Signature s0_empty = m.sign(k0, messageEmpty);
        Signature s1_empty = m.sign(k1, messageEmpty);
        Signature s0_short = m.sign(k0, messageShort);
        Signature s1_short = m.sign(k1, messageShort);
        Signature s0_long = m.sign(k0, messageLong);
        Signature s1_long = m.sign(k1, messageLong);

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

        assertTrue(m.verify(keys, combinedEmpty, messageEmpty, threshold));
        assertTrue(m.verify(keys, combinedShort, messageShort, threshold));
        assertTrue(m.verify(keys, combinedLong, messageLong, threshold));

        // incorrect data
        byte[] messageWrong1 = "hello worl".getBytes();
        byte[] messageWrong2 = "hello worldd".getBytes();

        assertFalse(m.verify(keys, combinedShort, messageWrong1, threshold));
        assertFalse(m.verify(keys, combinedShort, messageWrong2, threshold));
    }

    @Test
    public void testThreshold() throws NoSuchAlgorithmException, InvalidKeyException {
        // The following threshold-inputs are tested:
        //  - -1
        //  - 0
        //  - 1
        //  - keys.size - 1
        //  - keys.size
        //  - keys.size + 1
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
        try {
            m.verify(keys, combined, message, -1);
        } catch (IllegalArgumentException expected) {
            assert(expected.getMessage()).contains("Threshold must be at least 1");
        }

        // threshold = 0
        try {
            m.verify(keys, combined, message, 0);
        } catch (IllegalArgumentException expected) {
            assert(expected.getMessage()).contains("Threshold must be at least 1");
        }

        // threshold = 1
        assertTrue(m.verify(keys, combined, message, 1)); // (success)

        // threshold = keys.size - 1
        assertTrue(m.verify(keys, combined, message, keys.size() - 1)); // (success, unless Keys.length = 1)

        // threshold = keys.size
        assertTrue(m.verify(keys, combined, message, keys.size())); // (success)

        // threshold = keys.size + 1
        assertFalse(m.verify(keys, combined, message, keys.size() + 1));
    }

    @Test
    public void testSuccess() throws InvalidKeyException, NoSuchAlgorithmException {
        MultisigHMAC m = new MultisigHMAC(MultisigHMAC.Algorithm.HmacSHA256);

        Key k0 = m.generate(0);
        Key k1 = m.generate(1);
        Key k2 = m.generate(2);

        byte[] message = "hello world".getBytes();

        Signature s0 = m.sign(k0, message);
        Signature s2 = m.sign(k2, message);

        List<Signature> signatures = new ArrayList<>();
        signatures.add(s0);
        signatures.add(s2);

        Signature combined = m.combine(signatures);

        List<Key> keys = new ArrayList<>();
        keys.add(k0);
        keys.add(k1);
        keys.add(k2);
        int threshold = 2;

        System.out.println(m.verify(keys, combined, message, threshold));
    }
}