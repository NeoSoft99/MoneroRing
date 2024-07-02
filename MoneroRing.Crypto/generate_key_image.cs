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
    public static void hash_to_ec(byte[] key, byte[] res)
    {
        GroupElementP3 tmp;
        hash_to_ec(key, out tmp);
        GroupOperations.ge_p3_tobytes(res, 0, ref tmp);
    }

    static void hash_to_ec(byte[] key, out GroupElementP3 result)
    {
        GroupElementP2 point;
        GroupElementP1P1 point2;

        var keccak256 = new Nethereum.Util.Sha3Keccack();
        byte[] h = keccak256.CalculateHash(key);

        ge_fromfe_frombytes_vartime(out point, h);

        ge_mul8(out point2, ref point);
        GroupOperations.ge_p1p1_to_p3(out result, ref point2);
    }

    public static void generate_key_image(byte[] pub, byte[] sec, byte[] image)
    {
        GroupElementP3 point;
        GroupElementP2 point2;
        if (sc_check(sec) != 0)
            local_abort("invalid private key");
        hash_to_ec(pub, out point);
        //ge_scalarmult(out point2, ref sec, ref point);
        ge_scalarmult(out point2, sec, ref point);
        GroupOperations.ge_tobytes(image, 0, ref point2);
    }

}

