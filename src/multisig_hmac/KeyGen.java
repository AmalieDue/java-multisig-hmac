package multisig_hmac;

import java.security.SecureRandom;

public class KeyGen {
    IndexKey obj = new IndexKey();

    public KeyGen(int index, int KEYBYTES) {
        obj.index = index;
        obj.key = keygen(KEYBYTES);
    }

    public static byte[] keygen(int KEYBYTES) {
        byte[] Key = new byte[KEYBYTES];
        SecureRandom random = new SecureRandom();
        random.nextBytes(Key);

        return Key;
    }

    /*
    private class IndexKey {
        int index;
        byte[] key;
    }
     */
}
