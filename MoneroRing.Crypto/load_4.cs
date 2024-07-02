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
    static long load_4(byte[] input, int offset)
    {
        long result;
        result = (long)input[offset + 0];
        result |= ((long)input[offset + 1]) << 8;
        result |= ((long)input[offset + 2]) << 16;
        result |= ((long)input[offset + 3]) << 24;
        return result;
    }
}


