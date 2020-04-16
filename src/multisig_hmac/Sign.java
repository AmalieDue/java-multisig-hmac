package multisig_hmac;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Sign {
    Object[] IndexSign = new Object[2];

    public Sign(IndexKey KeyObj, byte[] Data, String Algorithm) throws InvalidKeyException, NoSuchAlgorithmException {
        IndexSign[0] = 1 << KeyObj.index;
        IndexSign[1] = sign(KeyObj, Data, Algorithm);
    }

    public static byte[] sign(IndexKey KeyObj, byte[] Data, String Algorithm) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac HMAC = Mac.getInstance(Algorithm);
        SecretKeySpec key = new SecretKeySpec(KeyObj.key, Algorithm);
        HMAC.init(key);

        return HMAC.doFinal(Data);
    }
}