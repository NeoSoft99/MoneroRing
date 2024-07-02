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

namespace MoneroRing.Crypto;

public static partial class RingSig
{
    public static byte[] hash_to_scalar(byte[] data)
    {
        //cn_fast_hash(data, length, reinterpret_cast < hash &> (res));
        var keccak256 = new Nethereum.Util.Sha3Keccack();
        byte[] res = keccak256.CalculateHash(data);

        sc_reduce32(res);
        return res;
    }

}

