package multisig_hmac;

import java.security.SecureRandom;

public class KeyGen extends IndexKey {

    public KeyGen(int index, int KEYBYTES) {
        //final byte[] Key = keygen(KEYBYTES);

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
