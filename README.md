# java-multisig-hmac

> Multisig scheme for HMAC authentication. A Maven project of [multisig-hmac](https://github.com/emilbayes/multisig-hmac) and [py-multisig-hmac](https://github.com/AmalieDue/py-multisig-hmac).

## Usage

Key management can happen in either of two modes, either by storing every of the component keys, or by storing a single master seed and using that to derive keys ad hoc.

Example using stored keys:

```java
package dk.hyperdivision.multisig_hmac;

import java.util.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class StoredKeys {

    public static void main(String[] args) {
    
        MultisigHMAC m = new MultisigHMAC(MultisigHMAC.Algorithm.HmacSHA256);
        KeyGen k0 = new KeyGen(0, m.KEYBYTES);
        KeyGen k1 = new KeyGen(1, m.KEYBYTES);
        KeyGen k2 = new KeyGen(2, m.KEYBYTES);

        byte[] Data = "hello world".getBytes();
        Sign s0 = new Sign(k0, Data, m.PRIMITIVE);
        Sign s2 = new Sign(k2, Data, m.PRIMITIVE);

        List<Sign> Signatures = new ArrayList<>();
        List<IndexKey> Keys = new ArrayList<>();
        Signatures.add(s0);
        Signatures.add(s2);
        Keys.add(k0);
        Keys.add(k1);
        Keys.add(k2);
        int Threshold = 2;

        Combine combined = new Combine(Signatures, m.BYTES);

        System.out.print(Verify.verify(Keys, combined, Data, Threshold, m.PRIMITIVE, m.BYTES));
    }
}
```

Example using derived keys:
```java
package dk.hyperdivision.multisig_hmac;

import java.util.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class DerivedKeys {

    public static void main(String[] args) {
    
        MultisigHMAC m = new MultisigHMAC(MultisigHMAC.Algorithm.HmacSHA256);
        
        byte[] Seed = DeriveKey.SeedGen(m.KEYBYTES);
        DeriveKey k0 = new DeriveKey(Seed, 0, m.PRIMITIVE);
        DeriveKey k1 = new DeriveKey(Seed, 1, m.PRIMITIVE);
        DeriveKey k2 = new DeriveKey(Seed, 2, m.PRIMITIVE);

        byte[] Data = "hello world".getBytes();
        Sign s0 = new Sign(k0, Data, m.PRIMITIVE);
        Sign s2 = new Sign(k2, Data, m.PRIMITIVE);

        List<Sign> Signatures = new ArrayList<>();
        Signatures.add(s0);
        Signatures.add(s2);
        int Threshold = 2;

        Combine combined = new Combine(Signatures, m.BYTES);

        System.out.print(VerifyDerived.verifyderived(Seed, combined, Data, Threshold, m.PRIMITIVE, m.KEYBYTES, m.BYTES));
    }
}
```

## Build

### Run Maven

```
mvn clean install
```

## License

[ISC](LICENSE)