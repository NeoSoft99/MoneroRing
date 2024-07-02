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
    /// <summary>
    /// Converts any random seed of any length to the seed suitable for generating Monero mnemonic.
    /// </summary>
    /// <param name="initial_seed">Random seed, any length.</param>
    /// <param name="mnemonic_seed">Monero mnemonic-compatible seed, 32 bytes (or null if result is false).</param>
    /// <returns>
    /// <c>true</c> if success; <paramref name="mnemonic_seed"/> contains the mnemonic seed.
    /// <c>false</c> if the resulting mnemonic seed is not compatible.
    /// </returns>
    public static bool generate_mnemonic_seed(byte[] initial_seed, out byte[] mnemonic_seed)
    {
        if (initial_seed == null || initial_seed.Length < 32)
        {
            mnemonic_seed = null;
            return false;
        }
        
        var keccak256 = new Nethereum.Util.Sha3Keccack();
        mnemonic_seed = keccak256.CalculateHash(initial_seed);
        
        if (!less32(mnemonic_seed, limit))
        {
            mnemonic_seed = null;
            return false;
        }

        sc_reduce32(mnemonic_seed);
        if (sc_isnonzero(mnemonic_seed) != 0)
            return true;
        
        mnemonic_seed = null;
        return false;
    }
}