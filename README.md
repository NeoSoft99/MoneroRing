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
### Generating keys
The following call generates a random pair of private and public keys that can be used in ring signature:
```
byte[] sec1 = new byte[32];
byte[] pub1 = new byte[32];
RingSig.generate_keys(pub1, sec1);
```
### Generating hash
The following call generates a hash that can be used in a ring signature. In actual implementation, this would be the hash
of the data block to be signed using the ring siganture.
```
string data = "MoneroRing library";
byte[] data_bytes = Encoding.UTF8.GetBytes(data);
var keccak256 = new Nethereum.Util.Sha3Keccack();
byte[] hash = keccak256.CalculateHash(data_bytes);
```
### Generating key image
The following call generates a key image of the given key:
```
byte[] image = new byte[32];
RingSig.generate_key_image(pub1, sec1, image);
```
### Generating ring signature
The following call generates a ring signature, with the key image, actual key at the second position, and two "decoy" public keys as the input:
```
var pubs = new byte[3][];
pubs[0] = pub1;
pubs[1] = pub2;
pubs[2] = pub3;
byte[] sig = RingSig.generate_ring_signature(hash, image, pubs, 3, sec2, 1);
```
### Validating ring signature
The following call validates ring signature:
```
bool ring_is_valid = RingSig.check_ring_signature(hash, image, pubs, 3, sig);
```
## License

MoneroRing library is licensed under MIT License: https://github.com/MystSafe/MoneroRing/blob/main/LICENSE
