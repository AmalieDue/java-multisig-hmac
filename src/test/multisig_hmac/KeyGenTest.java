package multisig_hmac;

import org.junit.Test;
import static org.junit.Assert.*;

class KeyGenTest {
    MultisigHMAC myObj = new MultisigHMAC(MultisigHMAC.Algorithm.HmacSHA256);

    @Test
    public void SimpleTest() {
        KeyGen k0 = new KeyGen(0, myObj.KEYBYTES);

        assertEquals(k0.key.length, myObj.KEYBYTES);
    }

    //@org.junit.jupiter.api.Test
    //void keygenTest() {

    //}
}