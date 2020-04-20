package multisig_hmac;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Sign {
    final int index;
    final byte[] sign;

    public Sign(IndexKey KeyObj, byte[] Data, String Algorithm) throws InvalidKeyException, NoSuchAlgorithmException {
        this.index = 1 << KeyObj.index;
        this.sign = sign(KeyObj, Data, Algorithm);
    }

    public static byte[] sign(IndexKey KeyObj, byte[] Data, String Algorithm) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac HMAC = Mac.getInstance(Algorithm);
        SecretKeySpec key = new SecretKeySpec(KeyObj.key, Algorithm);
        HMAC.init(key);

        return HMAC.doFinal(Data);
    }
}