using System;
using MoneroSharp.NaCl.Internal.Ed25519Ref10;
//using System.Diagnostics.Contracts;

namespace MoneroSharp.NaCl
{
    public static class Ed25519
    {
        /// <summary>
        /// Public Keys are 32 byte values. All possible values of this size a valid.
        /// </summary>
        public const int PublicKeySize = 32;
        /// <summary>
        /// Signatures are 64 byte values
        /// </summary>
        public const int SignatureSize = 64;
        /// <summary>
        /// Private key seeds are 32 byte arbitrary values. This is the form that should be generated and stored.
        /// </summary>
        public const int PrivateKeySeedSize = 32;
        /// <summary>
        /// A 64 byte expanded form of private key. This form is used internally to improve performance
        /// </summary>
        public const int ExpandedPrivateKeySize = 32 * 2;

        /// <summary>
        /// Verify Ed25519 signature
        /// </summary>
        /// <param name="signature">Signature bytes</param>
        /// <param name="message">Message</param>
        /// <param name="publicKey">Public key</param>
        /// <returns>True if signature is valid, false if it's not</returns>
        public static bool Verify(ArraySegment<byte> signature, ArraySegment<byte> message, ArraySegment<byte> publicKey)
        {
            //Contract.Requires<ArgumentException>(signature.Count == SignatureSize && publicKey.Count == PublicKeySize);
            if (signature.Count != SignatureSize || publicKey.Count != PublicKeySize)
            {
                throw new ArgumentException("Invalid signature or public key size.");
            }
            
            return Ed25519Operations.crypto_sign_verify(signature.Array, signature.Offset, message.Array, message.Offset, message.Count, publicKey.Array, publicKey.Offset);
        }

        /// <summary>
        /// Verify Ed25519 signature
        /// </summary>
        /// <param name="signature">Signature bytes</param>
        /// <param name="message">Message</param>
        /// <param name="publicKey">Public key</param>
        /// <returns>True if signature is valid, false if it's not</returns>
        public static bool Verify(byte[] signature, byte[] message, byte[] publicKey)
        {
            //Contract.Requires<ArgumentNullException>(signature != null && message != null && publicKey != null);
            //Contract.Requires<ArgumentException>(signature.Length == SignatureSize && publicKey.Length == PublicKeySize);
            if (signature == null || message == null || publicKey == null)
            {
                throw new ArgumentNullException("Signature, message, and public key cannot be null.");
            }

            if (signature.Length != SignatureSize || publicKey.Length != PublicKeySize)
            {
                throw new ArgumentException("Invalid signature or public key size.");
            }
            
            return Ed25519Operations.crypto_sign_verify(signature, 0, message, 0, message.Length, publicKey, 0);
        }

        /// <summary>
        /// Create new Ed25519 signature
        /// </summary>
        /// <param name="signature">Buffer for signature</param>
        /// <param name="message">Message bytes</param>
        /// <param name="expandedPrivateKey">Expanded form of private key</param>
        public static void Sign(ArraySegment<byte> signature, ArraySegment<byte> message, ArraySegment<byte> expandedPrivateKey)
        {
            //Contract.Requires<ArgumentNullException>(signature.Array != null && message.Array != null && expandedPrivateKey.Array != null);
            //Contract.Requires<ArgumentException>(expandedPrivateKey.Count == ExpandedPrivateKeySize);
            if (signature.Array == null || message.Array == null || expandedPrivateKey.Array == null)
            {
                throw new ArgumentNullException("Signature, message, and expanded private key cannot be null.");
            }

            if (expandedPrivateKey.Count != ExpandedPrivateKeySize)
            {
                throw new ArgumentException("Invalid expanded private key size.");
            }
            
            Ed25519Operations.crypto_sign(signature.Array, signature.Offset, message.Array, message.Offset, message.Count, expandedPrivateKey.Array, expandedPrivateKey.Offset);
        }

        /// <summary>
        /// Create new Ed25519 signature
        /// </summary>
        /// <param name="signature">Buffer for signature</param>
        /// <param name="message">Message bytes</param>
        /// <param name="expandedPrivateKey">Expanded form of private key</param>
        public static byte[] Sign(byte[] message, byte[] expandedPrivateKey)
        {
            //Contract.Requires<ArgumentNullException>(message != null && expandedPrivateKey != null);
            //Contract.Requires<ArgumentException>(expandedPrivateKey.Length == ExpandedPrivateKeySize);
            if (message == null || expandedPrivateKey == null)
            {
                throw new ArgumentNullException("Message and expanded private key cannot be null.");
            }

            if (expandedPrivateKey.Length != ExpandedPrivateKeySize)
            {
                throw new ArgumentException("Invalid expanded private key size.");
            }
            
            var signature = new byte[SignatureSize];
            Sign(new ArraySegment<byte>(signature), new ArraySegment<byte>(message), new ArraySegment<byte>(expandedPrivateKey));
            return signature;
        }

        /// <summary>
        /// Calculate public key from private key seed
        /// </summary>
        /// <param name="privateKeySeed">Private key seed value</param>
        /// <returns></returns>
        public static byte[] PublicKeyFromSeed(byte[] privateKeySeed)
        {
            //Contract.Requires<ArgumentNullException>(privateKeySeed != null);
            //Contract.Requires<ArgumentException>(privateKeySeed.Length == PrivateKeySeedSize);
            if (privateKeySeed == null)
            {
                throw new ArgumentNullException("Private key seed cannot be null.");
            }

            if (privateKeySeed.Length != PrivateKeySeedSize)
            {
                throw new ArgumentException("Invalid private key seed size.");
            }
            
            byte[] privateKey;
            byte[] publicKey;
            KeyPairFromSeed(out publicKey, out privateKey, privateKeySeed);
            CryptoBytes.Wipe(privateKey);
            return publicKey;
        }

        /// <summary>
        /// Calculate expanded form of private key from the key seed.
        /// </summary>
        /// <param name="privateKeySeed">Private key seed value</param>
        /// <returns>Expanded form of the private key</returns>
        public static byte[] ExpandedPrivateKeyFromSeed(byte[] privateKeySeed)
        {
            //Contract.Requires<ArgumentNullException>(privateKeySeed != null);
            //Contract.Requires<ArgumentException>(privateKeySeed.Length == PrivateKeySeedSize);
            if (privateKeySeed == null)
            {
                throw new ArgumentNullException("Private key seed cannot be null.");
            }

            if (privateKeySeed.Length != PrivateKeySeedSize)
            {
                throw new ArgumentException("Invalid private key seed size.");
            }

            byte[] privateKey;
            byte[] publicKey;
            KeyPairFromSeed(out publicKey, out privateKey, privateKeySeed);
            CryptoBytes.Wipe(publicKey);
            return privateKey;
        }

        /// <summary>
        /// Calculate key pair from the key seed.
        /// </summary>
        /// <param name="publicKey">Public key</param>
        /// <param name="expandedPrivateKey">Expanded form of the private key</param>
        /// <param name="privateKeySeed">Private key seed value</param>
        public static void KeyPairFromSeed(out byte[] publicKey, out byte[] expandedPrivateKey, byte[] privateKeySeed)
        {
            //Contract.Requires<ArgumentNullException>(privateKeySeed != null);
            //Contract.Requires<ArgumentException>(privateKeySeed.Length == PrivateKeySeedSize);
            if (privateKeySeed == null)
            {
                throw new ArgumentNullException("Private key seed cannot be null.");
            }

            if (privateKeySeed.Length != PrivateKeySeedSize)
            {
                throw new ArgumentException("Invalid private key seed size.");
            }
            
            var pk = new byte[PublicKeySize];
            var sk = new byte[ExpandedPrivateKeySize];

            Ed25519Operations.crypto_sign_keypair(pk, 0, sk, 0, privateKeySeed, 0);
            publicKey = pk;
            expandedPrivateKey = sk;
        }

        /// <summary>
        /// Calculate key pair from the key seed.
        /// </summary>
        /// <param name="publicKey">Public key</param>
        /// <param name="expandedPrivateKey">Expanded form of the private key</param>
        /// <param name="privateKeySeed">Private key seed value</param>
        public static void KeyPairFromSeed(ArraySegment<byte> publicKey, ArraySegment<byte> expandedPrivateKey, ArraySegment<byte> privateKeySeed)
        {
            //Contract.Requires<ArgumentNullException>(publicKey.Array != null && expandedPrivateKey.Array != null && privateKeySeed.Array != null);
            //Contract.Requires<ArgumentException>(expandedPrivateKey.Count == ExpandedPrivateKeySize && privateKeySeed.Count == PrivateKeySeedSize);
            //Contract.Requires<ArgumentException>(publicKey.Count == PublicKeySize);
            if (publicKey.Array == null || expandedPrivateKey.Array == null || privateKeySeed.Array == null)
            {
                throw new ArgumentNullException("Public key, expanded private key, and private key seed cannot be null.");
            }

            if (expandedPrivateKey.Count != ExpandedPrivateKeySize || privateKeySeed.Count != PrivateKeySeedSize || publicKey.Count != PublicKeySize)
            {
                throw new ArgumentException("Invalid key sizes.");
            }

            Ed25519Operations.crypto_sign_keypair(
                publicKey.Array, publicKey.Offset,
                expandedPrivateKey.Array, expandedPrivateKey.Offset,
                privateKeySeed.Array, privateKeySeed.Offset);
        }
    }
}