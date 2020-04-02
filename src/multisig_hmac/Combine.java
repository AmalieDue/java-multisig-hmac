package multisig_hmac;

import java.util.List;

public class Combine {

    public static Object[] combine(List<Sign> Signatures, int BYTES) {

        Object[] Combined = new Object[2];

        int BitField = 0;
        byte[] Sig = new byte[BYTES];

        for (Sign obj : Signatures) {
            BitField ^= (int) obj.IndexSign[0];
            Sig = xorBytes(Sig, (byte[]) obj.IndexSign[1]);
        }

        Combined[0] = BitField;
        Combined[1] = Sig;

        return Combined;
    }

    public static byte[] xorBytes(byte[] a, byte[] b) {

        byte[] result = new byte[32];
        for (int i = 0; i < Math.max(a.length,b.length); i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }

        return result;
    }
}