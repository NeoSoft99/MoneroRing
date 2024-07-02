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
	public static void ge_dsm_precomp(GroupElementCached[] r, ref GroupElementP3 s)
	{

        GroupElementP1P1 t;
        GroupElementP3 s2, u;
        GroupOperations.ge_p3_to_cached(out r[0], ref s);
        GroupOperations.ge_p3_dbl(out t, ref s); GroupOperations.ge_p1p1_to_p3(out s2, ref t);
        GroupOperations.ge_add(out t, ref s2, ref r[0]); GroupOperations.ge_p1p1_to_p3(out u, ref t); GroupOperations.ge_p3_to_cached(out r[1], ref u);
        GroupOperations.ge_add(out t, ref s2, ref r[1]); GroupOperations.ge_p1p1_to_p3(out u, ref t); GroupOperations.ge_p3_to_cached(out r[2], ref u);
        GroupOperations.ge_add(out t, ref s2, ref r[2]); GroupOperations.ge_p1p1_to_p3(out u, ref t); GroupOperations.ge_p3_to_cached(out r[3], ref u);
        GroupOperations.ge_add(out t, ref s2, ref r[3]); GroupOperations.ge_p1p1_to_p3(out u, ref t); GroupOperations.ge_p3_to_cached(out r[4], ref u);
        GroupOperations.ge_add(out t, ref s2, ref r[4]); GroupOperations.ge_p1p1_to_p3(out u, ref t); GroupOperations.ge_p3_to_cached(out r[5], ref u);
        GroupOperations.ge_add(out t, ref s2, ref r[5]); GroupOperations.ge_p1p1_to_p3(out u, ref t); GroupOperations.ge_p3_to_cached(out r[6], ref u);
        GroupOperations.ge_add(out t, ref s2, ref r[6]); GroupOperations.ge_p1p1_to_p3(out u, ref t); GroupOperations.ge_p3_to_cached(out r[7], ref u);
}

}

