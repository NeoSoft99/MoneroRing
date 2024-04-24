# MoneroRing

MoneroRing is .NET implementation of Monero ring signature and key image.

## What can MoneroRing do?

MoneroRing contains C# code of cryptographic operations with elliptic curves developed by Monero project and
required to generate and validate key images and ring signatures, which are the building blocks of private transactions.
MoneroRing references and extends MoneroSharp library created by Oğuzhan Eroğlu,
which implements cryptographic operations with Monero keys and addresses.

## Unit tests
The unit tests cover several basic crypto functions and the main ones such as generate_key_image, generate_ring_signature, and check_ring_signature.
The test data, including expected results, is taken from Monero test data which ensures 100% compatibility of binary inputs and outputs with the original C/C++ implementation.

## Using MoneroRing

### Memory management
The method signatures and implementation largely mimic the C/C++ style to maintain some degree of compatibility and readability, with the exception of memory management since the code is fully managed.
Thus, while there are memory allocations for buffers (typically implemented as byte[] arrays), there are no calls to free memory,
as this is handled by standard garbage collection.

Many objects are implemented as structs, which do not require explicit memory allocation or instance creation.
These are passed between methods by value, using the ref or out keywords.
The byte[] buffers must almost always be allocated before they are passed as method parameters.
## Generating key pair

The following call will generate a random pair of private and public keys that can be used in ring signature:
```
byte[] sec1 = new byte[32];
byte[] pub1 = new byte[32];
RingSig.generate_keys(pub1, sec1);
```

## License

MoneroRing library is licensed under MIT License: https://github.com/MystSafe/MoneroRing/blob/main/LICENSE