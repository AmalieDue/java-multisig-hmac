# java-multisig-hmac

> Multisig scheme for HMAC authentication. A Maven project of [multisig-hmac](https://github.com/emilbayes/multisig-hmac) and [py-multisig-hmac](https://github.com/AmalieDue/py-multisig-hmac).

## Usage

Key management can happen in either of two modes, either by storing every of the component keys, or by storing a single master seed and using that to derive keys ad hoc.

Example using stored keys:

```java
package dk.hyperdivision.multisig_hmac;

import java.util.*;

public class StoredKeys {

    public static void main(String[] args) {
    
        MultisigHMAC m = new MultisigHMAC(MultisigHMAC.Algorithm.HmacSHA256);

        Key k0 = m.generate(0);
        Key k1 = m.generate(1);
        Key k2 = m.generate(2);

        byte[] message = "hello world".getBytes();

        Signature s0 = m.sign(k0, message);
        Signature s2 = m.sign(k2, message);

        List<Signature> signatures = new ArrayList<>();
        signatures.add(s0);
        signatures.add(s2);
    
        Signature combined = m.combine(signatures);

        List<Key> keys = new ArrayList<>();
        keys.add(k0);
        keys.add(k1);
        keys.add(k2);
        int threshold = 2;

        System.out.println(m.verify(keys, combined, message, threshold));
    }
}
```

Example using derived keys:
```java
package dk.hyperdivision.multisig_hmac;

import java.util.*;

public class DerivedKeys {

    public static void main(String[] args) {
    
        DerivedMultisigHMAC m = new DerivedMultisigHMAC(DerivedMultisigHMAC.Algorithm.HmacSHA256);
        
        byte[] masterKey = m.generateMasterKey();

        Key k0 = m.generate(0, masterKey);
        Key k1 = m.generate(1, masterKey);
        Key k2 = m.generate(2, masterKey);

        byte[] message = "hello world".getBytes();

        Signature s0 = m.sign(k0, message);
        Signature s2 = m.sign(k2, message);

        List<Sign> signatures = new ArrayList<>();
        signatures.add(s0);
        signatures.add(s2);
        int threshold = 2;

        Signature combined = m.combine(signatures);

        System.out.print(m.verify(masterKey, combined, message, threshold));
    }
}
```

## License

[ISC](LICENSE)