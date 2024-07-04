/*
 * MoneroRing, C# .NET implementation of Monero keys, signatures, ring signatures, and key images
 * Github: https://github.com/MystSafe/MoneroRing
 *
 * Copyright (C) 2024, MystSafe (https://mystsafe.com)
 * Copyright (C) 2024, Author: crypticana <crypticana@proton.me>
 * MystSafe is the only privacy preserving password manager
 *
 * Licensed under MIT (See LICENSE file)
 */

using MoneroSharp.NaCl.Internal.Ed25519Ref10;

namespace MoneroRing.Crypto;

public static partial class RingSig
{
    // Calculates x = H_s(aR) + b
    // derivation is the shared secret (aR)
    // output_index specifies the output position in the transaction.
    // b (base) is the recipient’s private spend key  b .
    // derived_key is the secret key (x)
    public static void derive_secret_key(
    byte[] derivation,
    uint output_index,
    byte[] b,
    byte[] derived_key)
    {
        if (sc_check(b) != 0)
            local_abort("Invalid private key");
        
        byte[] scalar = derivation_to_scalar(derivation, output_index);
        sc_add(derived_key, b, scalar);
    }
}

// void crypto_ops::derive_secret_key(const key_derivation &derivation, size_t output_index,
// const secret_key &base, secret_key &derived_key) {
// ec_scalar scalar;
// assert(sc_check(&base) == 0);
// derivation_to_scalar(derivation, output_index, scalar);
// sc_add(&unwrap(derived_key), &unwrap(base), &scalar);
// }

