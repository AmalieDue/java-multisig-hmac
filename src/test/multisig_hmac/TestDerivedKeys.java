package multisig_hmac;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import static org.junit.Assert.*;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TestDerivedKeys {
    MultisigHMAC m = new MultisigHMAC(MultisigHMAC.Algorithm.HmacSHA256);

    AssertionError exception;

    // Inputs to the VerifyDerived method have the following equiv classes

    @Test
    public void Test_Masterseed() throws NoSuchAlgorithmException, InvalidKeyException {
        // Masterseed:
        //  - no masterseed
        //  - incorrect masterseed (length - 1, length, length + 1, wrong)
        //  - correct masterseed

        byte[] Seed = DeriveKey.SeedGen(m.KEYBYTES);

        DeriveKey k0 = new DeriveKey(Seed, 0, m.PRIMITIVE);
        DeriveKey k2 = new DeriveKey(Seed, 2, m.PRIMITIVE);

        byte[] Data = "".getBytes();

        Sign s0 = new Sign(k0, Data, m.PRIMITIVE);
        Sign s2 = new Sign(k2, Data, m.PRIMITIVE);

        List<Sign> Signatures = new ArrayList<>();
        Signatures.add(s0);
        Signatures.add(s2);

        Combine combined = new Combine(Signatures, m.BYTES);

        // no masterseed
        byte[] no_masterseed = "".getBytes();

        exception = assertThrows(AssertionError.class, () ->
                VerifyDerived.verifyderived(no_masterseed, combined, Data, 2, m.PRIMITIVE, m.KEYBYTES, m.BYTES));
        assertEquals("MasterSeed must be KEYBYTES long", exception.getMessage());

        // masterseed.length - 1
        byte[] short_masterseed = new byte[m.KEYBYTES - 1];
        System.arraycopy(Seed, 0, short_masterseed, 0, m.KEYBYTES - 1);

        exception = assertThrows(AssertionError.class, () ->
                VerifyDerived.verifyderived(short_masterseed, combined, Data, 2, m.PRIMITIVE, m.KEYBYTES, m.BYTES));
        assertEquals("MasterSeed must be KEYBYTES long", exception.getMessage());

        // masterseed.length
        assertTrue(VerifyDerived.verifyderived(Seed, combined, Data, 2, m.PRIMITIVE, m.KEYBYTES, m.BYTES));

        // masterseed.length + 1
        byte[] ZERO = new byte[] {0x00};
        byte[] long_masterseed = ByteBuffer.allocate(m.KEYBYTES + 1).put(Seed).put(ZERO).array();

        exception = assertThrows(AssertionError.class, () ->
                VerifyDerived.verifyderived(long_masterseed, combined, Data, 2, m.PRIMITIVE, m.KEYBYTES, m.BYTES));
        assertEquals("MasterSeed must be KEYBYTES long", exception.getMessage());

        // wrong masterseed
        byte[] Seed_new = DeriveKey.SeedGen(m.KEYBYTES);
        assertFalse(VerifyDerived.verifyderived(Seed_new, combined, Data, 2, m.PRIMITIVE, m.KEYBYTES, m.BYTES));
    }

    @Test
    public void Test_Signature() throws NoSuchAlgorithmException, InvalidKeyException {
        // The following Signature-inputs are tested:
        //  - empty signature
        //  - signature with wrong bitfield
        //  - signature with too many signatures
        //  - signature with too few signatures
        //  - signature with exactly correct signatures

        byte[] Seed = DeriveKey.SeedGen(m.KEYBYTES);

        DeriveKey k0 = new DeriveKey(Seed, 0, m.PRIMITIVE);
        DeriveKey k1 = new DeriveKey(Seed, 1, m.PRIMITIVE);
        DeriveKey k2 = new DeriveKey(Seed, 2, m.PRIMITIVE);
        byte[] Data = "".getBytes();
        Sign s0 = new Sign(k0, Data, m.PRIMITIVE);
        Sign s1 = new Sign(k1, Data, m.PRIMITIVE);
        Sign s2 = new Sign(k2, Data, m.PRIMITIVE);

        List<Sign> Signatures = new ArrayList<>();
        Signatures.add(s0);
        Signatures.add(s2);

        Combine combined = new Combine(Signatures, m.BYTES);

        // empty signature
        combined.sig = "".getBytes();

        exception = assertThrows(AssertionError.class, () ->
                VerifyDerived.verifyderived(Seed, combined, Data, 2, m.PRIMITIVE, m.KEYBYTES, m.BYTES));
        assertEquals("Signature must be BYTES long", exception.getMessage());

        // signature with wrong bitfield
        Combine combined1 = new Combine(Signatures, m.BYTES);
        combined1.bitfield = 0;
        assertFalse(VerifyDerived.verifyderived(Seed, combined1, Data, 2, m.PRIMITIVE, m.KEYBYTES, m.BYTES));

        // signature with too many signatures
        List<Sign> SignaturesTooMany = new ArrayList<>();
        SignaturesTooMany.add(s0);
        SignaturesTooMany.add(s1);
        SignaturesTooMany.add(s2);

        Combine combined2 = new Combine(SignaturesTooMany, m.BYTES);
        combined2.bitfield = combined1.bitfield;
        assertFalse(VerifyDerived.verifyderived(Seed, combined2, Data, 2, m.PRIMITIVE, m.KEYBYTES, m.BYTES));

        // signature with too few signatures
        Combine combined3 = new Combine(SignaturesTooMany, m.BYTES);
        combined3.sig = combined1.sig;
        assertFalse(VerifyDerived.verifyderived(Seed, combined3, Data, 2, m.PRIMITIVE, m.KEYBYTES, m.BYTES));
    }

    @Test
    public void Test_Data() throws NoSuchAlgorithmException, InvalidKeyException {
        // The following Data-inputs are tested:
        //  - Empty, less than block size, larger than block size
        //  - Incorrect data (length - 1, length, length + 1, wrong data)

        byte[] Seed = DeriveKey.SeedGen(m.KEYBYTES);

        DeriveKey k0 = new DeriveKey(Seed, 0, m.PRIMITIVE);
        DeriveKey k1 = new DeriveKey(Seed, 1, m.PRIMITIVE);

        // empty, less than block size, larger than block size
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
        Signatures_empty.add(s0_empty);
        Signatures_empty.add(s1_empty);
        Signatures_short.add(s0_short);
        Signatures_short.add(s1_short);
        Signatures_long.add(s0_long);
        Signatures_long.add(s1_long);

        Combine combined_empty = new Combine(Signatures_empty, m.BYTES);
        Combine combined_short = new Combine(Signatures_short, m.BYTES);
        Combine combined_long = new Combine(Signatures_long, m.BYTES);

        assertTrue(VerifyDerived.verifyderived(Seed, combined_empty, data_empty, 2, m.PRIMITIVE, m.KEYBYTES, m.BYTES));
        assertTrue(VerifyDerived.verifyderived(Seed, combined_short, data_short, 2, m.PRIMITIVE, m.KEYBYTES, m.BYTES));
        assertTrue(VerifyDerived.verifyderived(Seed, combined_long, data_long, 2, m.PRIMITIVE, m.KEYBYTES, m.BYTES));

        // incorrect data
        byte[] data_wrong1 = "hello worl".getBytes();
        byte[] data_wrong2 = "hello worldd".getBytes();

        assertFalse(VerifyDerived.verifyderived(Seed, combined_short, data_wrong1, 2, m.PRIMITIVE, m.KEYBYTES, m.BYTES));
        assertFalse(VerifyDerived.verifyderived(Seed, combined_short, data_wrong2, 2, m.PRIMITIVE, m.KEYBYTES, m.BYTES));
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

        byte[] Seed = DeriveKey.SeedGen(m.KEYBYTES);

        DeriveKey k0 = new DeriveKey(Seed, 0, m.PRIMITIVE);
        DeriveKey k1 = new DeriveKey(Seed, 1, m.PRIMITIVE);
        byte[] Data = "".getBytes();
        Sign s0 = new Sign(k0, Data, m.PRIMITIVE);
        Sign s1 = new Sign(k1, Data, m.PRIMITIVE);
        List<Sign> Signatures = new ArrayList<>();
        Signatures.add(s0);
        Signatures.add(s1);

        Combine combined = new Combine(Signatures, m.BYTES);

        // threshold = -1
        exception = assertThrows(AssertionError.class, () ->
                VerifyDerived.verifyderived(Seed, combined, Data, -1, m.PRIMITIVE, m.KEYBYTES, m.BYTES));
        assertEquals("Threshold must be at least 1", exception.getMessage());

        // threshold = 0;
        exception = assertThrows(AssertionError.class, () ->
                VerifyDerived.verifyderived(Seed, combined, Data, 0, m.PRIMITIVE, m.KEYBYTES, m.BYTES));
        assertEquals("Threshold must be at least 1", exception.getMessage());

        // threshold = 1;
        List<IndexKey> Keys = new ArrayList<>();
        Keys.add(k0);
        Keys.add(k1);
        assertTrue(VerifyDerived.verifyderived(Seed, combined, Data, 1, m.PRIMITIVE, m.KEYBYTES, m.BYTES)); // (success)

        // threshold = Keys.length - 1
        assertTrue(VerifyDerived.verifyderived(Seed, combined, Data, Keys.size() - 1, m.PRIMITIVE, m.KEYBYTES, m.BYTES)); // (success, unless Keys.length = 1)

        // threshold = Keys.length
        assertTrue(VerifyDerived.verifyderived(Seed, combined, Data, Keys.size(), m.PRIMITIVE, m.KEYBYTES, m.BYTES)); // (success)

        // threshold = Keys.length + 1
        assertFalse(VerifyDerived.verifyderived(Seed, combined, Data, Keys.size() + 1, m.PRIMITIVE, m.KEYBYTES, m.BYTES));
    }

    @Test
    public void Test_Success() throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] Seed = DeriveKey.SeedGen(m.KEYBYTES);
        DeriveKey k0 = new DeriveKey(Seed, 0, m.PRIMITIVE);
        DeriveKey k1 = new DeriveKey(Seed, 1, m.PRIMITIVE);
        DeriveKey k2 = new DeriveKey(Seed, 2, m.PRIMITIVE);

        byte[] Data = "hello world".getBytes();
        Sign s0 = new Sign(k0, Data, m.PRIMITIVE);
        Sign s2 = new Sign(k2, Data, m.PRIMITIVE);

        List<Sign> Signatures = new ArrayList<>();
        Signatures.add(s0);
        Signatures.add(s2);

        Combine combined = new Combine(Signatures, m.BYTES);

        assertTrue(VerifyDerived.verifyderived(Seed, combined, Data, 2, m.PRIMITIVE, m.KEYBYTES, m.BYTES));
    }
}