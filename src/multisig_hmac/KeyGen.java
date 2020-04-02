package multisig_hmac;

import java.security.SecureRandom;

public class KeyGen {

    Object[] IndexKey = new Object[2];

    public KeyGen(int index, int KEYBYTES) {

        IndexKey[0] = index;
        IndexKey[1] = keygen(KEYBYTES);
    }

    public static byte[] keygen(int KEYBYTES) {

        byte[] Key = new byte[KEYBYTES];
        SecureRandom random = new SecureRandom();
        random.nextBytes(Key);

        return Key;
    }
}