package multisig_hmac;

/**
 * IndexKey represents an instance of a index + cryptographically random key.
 *
 * IndexKey is extended by the classes KeyGen and DeriveKey, which are two different
 * ways of constructing and initializing keys.
 *
 * @author Amalie Due Jensen
 */
abstract class IndexKey {
    int index;
    byte[] key;
}
