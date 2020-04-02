# multisig-hmac-java-version

> Multisig scheme for HMAC authentication. Java implementation of [multisig-hmac](https://github.com/emilbayes/multisig-hmac).

## Usage
Key management can happen in either of two modes, either by storing every of the component keys, or by storing a single master seed and using that to derive keys ad hoc.

Example using stored keys:

```java
public static void main(String[] args) throws Exception {
    MultisigHMAC myObj = new MultisigHMAC(Algorithm.HmacSHA256);

    KeyGen k0 = new KeyGen(0, myObj.KEYBYTES);
    Keygen k1 = new KeyGen(1, myObj.KEYBYTES);
    Keygen k2 = new KeyGen(2, myObj.KEYBYTES);

    byte[] Data = "hello world".getBytes();

    List<Sign> Signatures = new ArrayList<>();
    Signatures.add(new Sign(k0.IndexKey, Data, myObj.PRIMITIVE));
    Signatures.add(new Sign(k2.IndexKey, Data, myObj.PRIMITIVE));

    Object[] out = Combine.combine(Signatures, myObj.BYTES);

    int Threshold = 2;
    List<Object[]> Keys = new ArrayList<>();
    Keys.add(k0.IndexKey);
    Keys.add(k1.IndexKey);
    Keys.add(k2.IndexKey);

    System.out.println(Verify.verify(Keys, out, Data, Threshold, myObj.PRIMITIVE, myObj.BYTES));
}
```

Example using derived keys:
```java
public static void main(String[] args) throws Exception {
    MultisigHMAC myObj = new MultisigHMAC(Algorithm.HmacSHA256);

    byte[] Seed = DeriveKey.SeedGen(myObj.KEYBYTES);

    DeriveKey k0 = new DeriveKey(Seed, 0, myObj.PRIMITIVE);
    DeriveKey k1 = new DeriveKey(Seed, 1, myObj.PRIMITIVE);
    DeriveKey k2 = new DeriveKey(Seed, 2, myObj.PRIMITIVE);

    byte[] Data = "hello world".getBytes();

    List<Sign> Signatures = new ArrayList<>();
    Signatures.add(new Sign(k0.IndexKey, Data, myObj.PRIMITIVE));
    Signatures.add(new Sign(k2.IndexKey, Data, myObj.PRIMITIVE));

    Object[] out = Combine.combine(Signatures, myObj.BYTES);

    int Threshold = 2;

    System.out.println(VerifyDerived.verifyderived(Seed, out, Data, Threshold, myObj.PRIMITIVE, myObj.BYTES));
}
```

## API

## License

[ISC](LICENSE)
