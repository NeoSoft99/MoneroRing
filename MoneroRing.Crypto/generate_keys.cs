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
    public static void generate_keys(byte[] pub, byte[] sec)
    {
        GroupElementP3 point;
        random_scalar(sec);
        sc_reduce32(sec);
        GroupOperations.ge_scalarmult_base(out point, sec, 0);
        GroupOperations.ge_p3_tobytes(pub, 0, ref point);
    }

}

