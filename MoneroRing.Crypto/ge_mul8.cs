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
	public static void ge_mul8(out GroupElementP1P1 r, ref GroupElementP2 t)
	{
        GroupElementP2 u;
        GroupOperations.ge_p2_dbl(out r, ref t);
        GroupOperations.ge_p1p1_to_p2(out u, ref r);
        GroupOperations.ge_p2_dbl(out r, ref u);
        GroupOperations.ge_p1p1_to_p2(out u, ref r);
        GroupOperations.ge_p2_dbl(out r, ref u);
    }

}

