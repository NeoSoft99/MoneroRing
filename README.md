# MoneroRing

MoneroRing is .NET implementation of Monero ring signature and key image.

## What is ring signature?

Ring signatures are a form of digital signature that allow a member of a group to sign a message on behalf of the group without revealing which member actually produced the signature. This type of signature offers anonymity and is crucial in various applications where privacy is paramount, such as in cryptocurrency transactions.

**Group formation:** The basis of a ring signature is a group of potential signers, each possessing their own unique key pair (public and private keys). The actual signer forms a "ring" with the public keys of the other group members.

**Signing process:** When a member wants to sign a document or a transaction, they use their private key along with the public keys of the other members in the group. The process combines these keys to produce a unique signature that validates the message. Importantly, the signature algorithm ensures that the identity of the actual signer remains hidden among the group members.

**Signature verification:** 
Anyone can verify the signature using the public keys of all the group members. The verifier can confirm that the signature was created by someone in the group, but they cannot determine which specific member signed it.

**Anonymity and security:** The key feature of ring signatures is their ability to provide anonymity while still ensuring the authenticity of the signed message. This is particularly useful in scenarios where trust and privacy are needed simultaneously.

**Non-reusability:** Each ring signature is unique to each transaction. Even if the same group of users forms the ring, the signature will be different each time due to the transaction details and the randomness introduced during the signing process.

## Ring signatures in Monero
In Monero, ring signatures play a crucial role in maintaining privacy and anonymity for its users. This cryptographic technology allows a transaction to be signed by a group, yet it obscures the identity of the specific individual who signed it. Here's how it works:

**Anonymity:** When a Monero user initiates a transaction, their identity is hidden by combining their transaction details with past transaction outputs on the blockchain. This forms a group or "ring" of possible signers, making it computationally infeasible to determine who exactly initiated the transaction.

**Untraceability:** Each output in a transaction can only be spent once thanks to the ring signature, which validates the transaction without revealing which of the group members' keys was used. This ensures that each transaction is untraceable to a specific user, adding a layer of security against tracking and surveillance.

**Decentralization and trustlessness:** Ring signatures reinforce the decentralized and trustless nature of Monero. Users don’t need to rely on any external authority to keep their transactions private — the cryptographic mechanism itself ensures secrecy and security.

**Resistance to analysis:** By using ring signatures, Monero complicates blockchain analysis, making it extremely difficult for analysts to draw correlations between transactions. This is especially beneficial for users in regions where financial transactions are heavily monitored or where financial privacy is paramount.

In summary, ring signatures are essential to Monero's architecture, providing a robust method of preserving privacy by hiding the sender's identity in a group of potential signers. This makes Monero an attractive option for users seeking confidentiality in their digital transactions.

## Ring signatures in MystSafe
In MystSafe, ring signatures are used to enhance the privacy and security of its licensing model. Here's how they are specifically implemented:

**License token system:** MystSafe utilizes crypto tokens as licenses for transactions within its network. These tokens are unique to each transaction, ensuring that they cannot be reused, which aligns with the non-reusability feature of ring signatures.

**Enhanced privacy:** By integrating ring signatures, MystSafe allows users to conduct data operations without revealing which account initiated them. This is achieved by obscuring the sender among a group of potential signers, thereby protecting user identities.

**Isolating payments from user activities:** Ring signatures enable the cryptographic separation of the license from the payment process. This means that even if the payment for premium license is made through methods that could reveal identity, such as credit cards, your identity cannot be linked back to the account or the data blocks.

## What is key image?
Key images are a fundamental component in certain cryptographic protocols, particularly those involving ring signatures, like those used in cryptocurrencies such as Monero. A key image is a cryptographic construct designed to prevent double-spending in digital currencies without compromising the anonymity of the transactions. A key image is a unique piece of data associated with a specific private key in a digital transaction. It is generated by the sender of the transaction and forms an integral part of the ring signature mechanism.

### How key images work
**Generation:** A key image is created using the sender's private key. The exact mathematical formula varies depending on the specific implementation of the ring signatures, but generally, it involves cryptographic operations that combine the private key with public parameters of the system to produce a unique output that can't be linked directly back to the private key.

**Uniqueness:** The key image is unique to each private key but does not reveal the identity of the key holder. It is impossible to derive the private key from the key image, preserving the security of the key holder's identity.

**Role in preventing double-spending:** In cryptocurrencies, the key image is used to ensure that each piece of a digital token can be spent only once. When a transaction is initiated, the key image is recorded on the blockchain. Network participants can check this list of key images to verify that no previous transaction has included the same key image, thereby preventing double-spending while maintaining user anonymity.

**Verification:** Though the key image prevents the reuse of output (tokens), it does not compromise the anonymity provided by ring signatures. The network verifies that the key image corresponds to a valid ring signature without revealing which group member's key was used to generate it.

### Importance in privacy-centric cryptocurrencies
In privacy-focused cryptocurrencies like Monero, key images are crucial for balancing anonymity with the integrity of the transaction system. They allow the network to verify the legitimacy of transactions without linking them back to individual users’ identities, thereby supporting both privacy and security.

## Application of key images in MystSafe
**License token transactions:** In MystSafe, each license token (representing the right to use services such as data storage or transmission) is associated with a unique key image. This key image is generated from the private key of the license holder, who initiates the transaction.

**Prevention of double-spending:** When a user performs a data transaction—such as transferring a license token to another account or using it to access a service—the key image for that token is recorded on MystSafe’s ledger. This ledger allows to verify that each key image has not been used before, thereby ensuring that each license token is spent only once.

**Maintaining anonymity:** Although the key image is unique and prevents the token from being reused, it does not reveal the identity of the user. This is because the key image, while derived from a user's private key, does not expose the key itself. This setup allows MystSafe to maintain user anonymity, a core aspect of its privacy-focused architecture.

**Role in ring signatures:** MystSafe utilizes ring signatures to obscure the specifics of transaction participants. The key image is a critical component in these signatures, ensuring that while the group of possible signers (public keys) is visible, the actual signer (and thus the spender of the license token) remains anonymous. The presence of the key image in the transaction verifies that the signature is valid and the license token has not been spent previously, without linking back to any specific user.

By incorporating key images in this way, MystSafe ensures a secure, private, and efficient mechanism for handling data transactions and services within its ecosystem, reinforcing its commitment to user privacy and data security.

## What can MoneroRing library do?
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
