package multisig_hmac;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Sign represents a sign of data with a key
 *
 * @author Amalie Due Jensen
 */
public class Sign {
    final int index;
    final byte[] sign;

    /**
     * Constructs and initializes a sign of data with a key
     *
     * A list of instances of Sign can be passed to an instance of Combine
     *
     * @param KeyObj - instance of IndexKey
     * @param Data - data which should be signed
     * @param Algorithm - algorithm used for HMAC
     * @throws InvalidKeyException - if the given key is inappropriate for initializing this HMAC
     * @throws NoSuchAlgorithmException - if the specified algorithm is not available
     */
    public Sign(IndexKey KeyObj, byte[] Data, String Algorithm) throws InvalidKeyException, NoSuchAlgorithmException {
        this.index = 1 << KeyObj.index;
        this.sign = sign(KeyObj, Data, Algorithm);
    }

    /**
     * Independently signs data with a key
     *
     * @param KeyObj - instance of indexKey
     * @param Data - data which should be signed
     * @param Algorithm - algorithm used for HMAC
     * @return sign of data
     * @throws InvalidKeyException - if the given key is inappropriate for initializing this HMAC
     * @throws NoSuchAlgorithmException - if the specified algorithm is not available
     */
    public static byte[] sign(IndexKey KeyObj, byte[] Data, String Algorithm) throws InvalidKeyException, NoSuchAlgorithmException {
        Mac HMAC = Mac.getInstance(Algorithm);
        SecretKeySpec key = new SecretKeySpec(KeyObj.key, Algorithm);
        HMAC.init(key);

        return HMAC.doFinal(Data);
    }
}