package dk.hyperdivision.multisig_hmac;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class TestDerivedKeys {
    DerivedMultisigHMAC m = new DerivedMultisigHMAC(MultisigHMAC.Algorithm.HmacSHA256);

    AssertionError exception;

    // Inputs to the VerifyDerived method have the following equiv classes

    @Test
    public void testMasterSeed() throws NoSuchAlgorithmException, InvalidKeyException {
        // masterSeed:
        //  - no masterSeed
        //  - incorrect masterSeed (length - 1, length, length + 1, wrong)
        //  - correct masterSeed

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

        // no masterseed
        byte[] noMasterseed = "".getBytes();

        exception = assertThrows(AssertionError.class, () ->
                m.verify(noMasterseed, combined, message, 2));
        assertEquals("MasterSeed must be KEYBYTES long", exception.getMessage());

        // masterseed.length - 1
        byte[] shortMasterseed = new byte[m.getKEYBYTES() - 1];
        System.arraycopy(masterKey, 0, shortMasterseed, 0, m.getKEYBYTES() - 1);

        exception = assertThrows(AssertionError.class, () ->
                m.verify(shortMasterseed, combined, message, 2));
        assertEquals("MasterSeed must be KEYBYTES long", exception.getMessage());

        // masterseed.length
        assertTrue(m.verify(masterKey, combined, message, 2));

        // masterseed.length + 1
        byte[] ZERO = new byte[] {0x00};
        byte[] longMasterseed = ByteBuffer.allocate(m.getKEYBYTES() + 1).put(masterKey).put(ZERO).array();

        exception = assertThrows(AssertionError.class, () ->
                m.verify(longMasterseed, combined, message, 2));
        assertEquals("MasterSeed must be KEYBYTES long", exception.getMessage());

        // wrong masterseed
        byte[] seedNew = m.generateMasterKey();
        assertFalse(m.verify(seedNew, combined, message, 2));
    }

    @Test
    public void Test_Signature() throws NoSuchAlgorithmException, InvalidKeyException {
        // The following Signature-inputs are tested:
        //  - empty signature
        //  - signature with wrong bitfield
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

        exception = assertThrows(AssertionError.class, () ->
                m.verify(masterKey, combined, message, 2));
        assertEquals("Signature must be BYTES long", exception.getMessage());

        // signature with wrong bitfield
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
    public void Test_Data() throws NoSuchAlgorithmException, InvalidKeyException {
        // The following Data-inputs are tested:
        //  - Empty, less than block size, larger than block size
        //  - Incorrect data (length - 1, length, length + 1, wrong data)

        byte[] masterKey = m.generateMasterKey();

        Key k0 = m.generate(0, masterKey);
        Key k1 = m.generate(1, masterKey);

        // empty, less than block size, larger than block size
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
        signaturesEmpty.add(s0_empty);
        signaturesEmpty.add(s1_empty);
        signaturesShort.add(s0_short);
        signaturesShort.add(s1_short);
        signaturesLong.add(s0_long);
        signaturesLong.add(s1_long);

        Signature combined_empty = m.combine(signaturesEmpty);
        Signature combined_short = m.combine(signaturesShort);
        Signature combined_long = m.combine(signaturesLong);

        assertTrue(m.verify(masterKey, combined_empty, dataEmpty, 2));
        assertTrue(m.verify(masterKey, combined_short, dataShort, 2));
        assertTrue(m.verify(masterKey, combined_long, dataLong, 2));

        // incorrect data
        byte[] data_wrong1 = "hello worl".getBytes();
        byte[] data_wrong2 = "hello worldd".getBytes();

        assertFalse(m.verify(masterKey, combined_short, data_wrong1, 2));
        assertFalse(m.verify(masterKey, combined_short, data_wrong2, 2));
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
        exception = assertThrows(AssertionError.class, () ->
                m.verify(masterKey, combined, message, -1));
        assertEquals("Threshold must be at least 1", exception.getMessage());

        // threshold = 0;
        exception = assertThrows(AssertionError.class, () ->
                m.verify(masterKey, combined, message, 0));
        assertEquals("Threshold must be at least 1", exception.getMessage());

        // threshold = 1;
        List<Key> Keys = new ArrayList<>();
        Keys.add(k0);
        Keys.add(k1);
        assertTrue(m.verify(masterKey, combined, message, 1)); // (success)

        // threshold = Keys.length - 1
        assertTrue(m.verify(masterKey, combined, message, Keys.size() - 1)); // (success, unless Keys.length = 1)

        // threshold = Keys.length
        assertTrue(m.verify(masterKey, combined, message, Keys.size())); // (success)

        // threshold = Keys.length + 1
        assertFalse(m.verify(masterKey, combined, message, Keys.size() + 1));
    }

    @Test
    public void Test_Success() throws NoSuchAlgorithmException, InvalidKeyException {
        DerivedMultisigHMAC m = new DerivedMultisigHMAC(DerivedMultisigHMAC.Algorithm.HmacSHA256);

        byte[] masterKey = m.generateMasterKey();

        Key k0 = m.generate(0, masterKey);
        Key k1 = m.generate(1, masterKey);
        Key k2 = m.generate(2, masterKey);

        byte[] message = "hello world".getBytes();

        Signature s0 = m.sign(k0, message);
        Signature s1 = m.sign(k1, message);
        Signature s2 = m.sign(k2, message);

        List<Signature> Signatures = new ArrayList<>();
        Signatures.add(s0);
        Signatures.add(s1);
        Signatures.add(s2);

        Signature combined = m.combine(Signatures);

        int Threshold = 2;

        System.out.println(m.verify(masterKey, combined, message, Threshold));
    }
}
