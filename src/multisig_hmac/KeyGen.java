package multisig_hmac;

import java.security.SecureRandom;

public class KeyGen extends IndexKey {
    //final int index;
    //final byte[] key;

    public KeyGen(int index, int KEYBYTES) {
        this.index = index;
        this.key = keygen(KEYBYTES);
    }

    public static byte[] keygen(int KEYBYTES) {
        byte[] Key = new byte[KEYBYTES];
        SecureRandom random = new SecureRandom();
        random.nextBytes(Key);

        return Key;
    }
}
