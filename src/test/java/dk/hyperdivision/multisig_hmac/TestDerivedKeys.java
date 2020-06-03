package dk.hyperdivision.multisig_hmac;

import org.junit.jupiter.api.Test;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TestDerivedKeys {
    DerivedMultisigHMAC m = new DerivedMultisigHMAC(MultisigHMAC.Algorithm.HmacSHA256);

    // Inputs to the DerivedMultisigHMAC.verify method have the following equiv classes

    @Test
    public void testMasterKey() throws NoSuchAlgorithmException, InvalidKeyException {
        // master key:
        //  - no master key
        //  - incorrect master key (length - 1, length, length + 1, wrong)
        //  - correct master key

        byte[] masterKey = m.generateMasterKey();

        Key k0 = m.generate(0, masterKey);
        Key k2 = m.generate(2, masterKey);

        byte[] message = "".getBytes();

        Signature s0 = m.sign(k0, message);
        Signature s2 = m.sign(k2, message);

        List<Signature> signatures = new ArrayList<>();
        signatures.add(s0);
        signatures.add(s2);

        Signature combined = m.combine(signatures);

        // no master key
        byte[] noMasterKey = "".getBytes();

        try {
            m.verify(noMasterKey, combined, message, 2);
        } catch (IllegalArgumentException expected) {
            assert(expected.getMessage()).contains("Master key must be KEYBYTES long");
        }

        // masterKey.length - 1
        byte[] shortMasterKey = new byte[m.getKEYBYTES() - 1];
        System.arraycopy(masterKey, 0, shortMasterKey, 0, m.getKEYBYTES() - 1);

        try {
            m.verify(shortMasterKey, combined, message, 2);
        } catch (IllegalArgumentException expected) {
            assert(expected.getMessage()).contains("Master key must be KEYBYTES long");
        }

        // masterKey.length
        assertTrue(m.verify(masterKey, combined, message, 2));

        // masterKey.length + 1
        byte[] ZERO = new byte[] {0x00};
        byte[] longMasterKey = ByteBuffer.allocate(m.getKEYBYTES() + 1).put(masterKey).put(ZERO).array();

        try {
            m.verify(longMasterKey, combined, message, 2);
        } catch (IllegalArgumentException expected) {
            assert(expected.getMessage()).contains("Master key must be KEYBYTES long");
        }

        // wrong master key
        byte[] keyNew = m.generateMasterKey();
        assertFalse(m.verify(keyNew, combined, message, 2));
    }

    @Test
    public void testSignature() throws NoSuchAlgorithmException, InvalidKeyException {
        // The following signature-inputs are tested:
        //  - empty signature
        //  - signature with wrong index
        //  - signature with too many signatures
        //  - signature with too few signatures
        //  - signature with exactly correct signatures

        byte[] masterKey = m.generateMasterKey();

        Key k0 = m.generate(0, masterKey);
        Key k1 = m.generate(1, masterKey);
        Key k2 = m.generate(2, masterKey);
        byte[] message = "".getBytes();
        Signature s0 = m.sign(k0, message);
        Signature s1 = m.sign(k1, message);
        Signature s2 = m.sign(k2, message);

        List<Signature> signatures = new ArrayList<>();
        signatures.add(s0);
        signatures.add(s2);

        Signature combined = m.combine(signatures);

        // empty signature
        combined.signature = "".getBytes();

        try {
            m.verify(masterKey, combined, message, 2);
        } catch (IllegalArgumentException expected) {
            assert(expected.getMessage()).contains("Signature must be BYTES long");
        }

        // signature with wrong index
        Signature combined1 = m.combine(signatures);
        combined1.index = 0;
        assertFalse(m.verify(masterKey, combined1, message, 2));

        // signature with too many signatures
        List<Signature> signaturesTooMany = new ArrayList<>();
        signaturesTooMany.add(s0);
        signaturesTooMany.add(s1);
        signaturesTooMany.add(s2);

        Signature combined2 = m.combine(signaturesTooMany);
        combined2.index = combined1.index;
        assertFalse(m.verify(masterKey, combined2, message, 2));

        // signature with too few signatures
        Signature combined3 = m.combine(signaturesTooMany);
        combined3.signature = combined1.signature;
        assertFalse(m.verify(masterKey, combined3, message, 2));
    }

    @Test
    public void testMessage() throws NoSuchAlgorithmException, InvalidKeyException {
        // The following message-inputs are tested:
        //  - Empty, less than block size, larger than block size
        //  - Incorrect message (length - 1, length, length + 1, wrong message)

        byte[] masterKey = m.generateMasterKey();

        Key k0 = m.generate(0, masterKey);
        Key k1 = m.generate(1, masterKey);

        // empty, less than block size, larger than block size
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
        signaturesEmpty.add(s0_empty);
        signaturesEmpty.add(s1_empty);
        signaturesShort.add(s0_short);
        signaturesShort.add(s1_short);
        signaturesLong.add(s0_long);
        signaturesLong.add(s1_long);

        Signature combinedEmpty = m.combine(signaturesEmpty);
        Signature combinedShort = m.combine(signaturesShort);
        Signature combinedLong = m.combine(signaturesLong);

        assertTrue(m.verify(masterKey, combinedEmpty, messageEmpty, 2));
        assertTrue(m.verify(masterKey, combinedShort, messageShort, 2));
        assertTrue(m.verify(masterKey, combinedLong, messageLong, 2));

        // incorrect message
        byte[] messageWrong1 = "hello worl".getBytes();
        byte[] messageWrong2 = "hello worldd".getBytes();

        assertFalse(m.verify(masterKey, combinedShort, messageWrong1, 2));
        assertFalse(m.verify(masterKey, combinedShort, messageWrong2, 2));
    }

    @Test
    public void testThreshold() throws NoSuchAlgorithmException, InvalidKeyException {
        // The following threshold-inputs are tested:
        //  - -1
        //  - 0
        //  - 1
        //  - keys.length - 1
        //  - keys.length
        //  - keys.length + 1
        //  - Some happy path

        byte[] masterKey = m.generateMasterKey();

        Key k0 = m.generate(0, masterKey);
        Key k1 = m.generate(1, masterKey);
        byte[] message = "".getBytes();
        Signature s0 = m.sign(k0, message);
        Signature s1 = m.sign(k1, message);
        List<Signature> signatures = new ArrayList<>();
        signatures.add(s0);
        signatures.add(s1);

        Signature combined = m.combine(signatures);

        // threshold = -1
        try {
            m.verify(masterKey, combined, message, -1);
        } catch (IllegalArgumentException expected) {
            assert(expected.getMessage()).contains("Threshold must be at least 1");
        }

        // threshold = 0;
        try {
            m.verify(masterKey, combined, message, 0);
        } catch (IllegalArgumentException expected) {
            assert(expected.getMessage()).contains("Threshold must be at least 1");
        }

        // threshold = 1;
        List<Key> keys = new ArrayList<>();
        keys.add(k0);
        keys.add(k1);
        assertTrue(m.verify(masterKey, combined, message, 1)); // (success)

        // threshold = keys.length - 1
        assertTrue(m.verify(masterKey, combined, message, keys.size() - 1)); // (success, unless Keys.length = 1)

        // threshold = keys.length
        assertTrue(m.verify(masterKey, combined, message, keys.size())); // (success)

        // threshold = keys.length + 1
        assertFalse(m.verify(masterKey, combined, message, keys.size() + 1));
    }

    @Test
    public void testSuccess() throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] masterKey = m.generateMasterKey();

        Key k0 = m.generate(0, masterKey);
        Key k1 = m.generate(1, masterKey);
        Key k2 = m.generate(2, masterKey);

        byte[] message = "hello world".getBytes();

        Signature s0 = m.sign(k0, message);
        Signature s2 = m.sign(k2, message);

        List<Signature> signatures = new ArrayList<>();
        signatures.add(s0);
        signatures.add(s2);

        Signature combined = m.combine(signatures);

        int threshold = 2;

        System.out.println(m.verify(masterKey, combined, message, threshold));
    }
}