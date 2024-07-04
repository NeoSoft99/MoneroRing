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
    // Calculates P = Hs(rA)G + B aka output stealth address
    // derivation is the shared secret rA or aR
    // output_index specifies the output position in the transaction.
    // B (base) is the recipient’s public spend key  B.
    // derived_key is the output public key (P)
    public static bool derive_public_key(
        byte[] derivation,
        uint output_index,
        byte[] B,
        byte[] derived_key)
    {
        GroupElementP3 point1;
        GroupElementP3 point2;
        GroupElementCached point3;
        GroupElementP1P1 point4;
        GroupElementP2 point5;
        
        if (ge_frombytes_vartime(out point1, B) != 0)
        {
            return false;
        }

        byte[] scalar = derivation_to_scalar(derivation, output_index);
        GroupOperations.ge_scalarmult_base(out point2, scalar, 0);
        GroupOperations.ge_p3_to_cached(out point3, ref point2);
        GroupOperations.ge_add(out point4, ref point1, ref point3);
        GroupOperations.ge_p1p1_to_p2(out point5, ref point4);
        GroupOperations.ge_tobytes(derived_key, 0, ref point5);
        return true;
    }
}

/*bool crypto_ops::derive_public_key(const key_derivation &derivation, size_t output_index,
const public_key &base, public_key &derived_key) {
    ec_scalar scalar;
    ge_p3 point1;
    ge_p3 point2;
    ge_cached point3;
    ge_p1p1 point4;
    ge_p2 point5;
    if (ge_frombytes_vartime(&point1, &base) != 0) {
        return false;
    }
    derivation_to_scalar(derivation, output_index, scalar);
    ge_scalarmult_base(&point2, &scalar);
    ge_p3_to_cached(&point3, &point2);
    ge_add(&point4, &point1, &point3);
    ge_p1p1_to_p2(&point5, &point4);
    ge_tobytes(&derived_key, &point5);
    return true;
}*/
