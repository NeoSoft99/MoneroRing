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
	public static void ge_double_scalarmult_precomp_vartime(out GroupElementP2 r, byte[] a, ref GroupElementP3 A, byte[] b, GroupElementCached[] Bi) // ge_dsmp type is array of 8 GroupElementCached
    {
        //ge_dsmp Ai; /* A, 3A, 5A, 7A, 9A, 11A, 13A, 15A */
        GroupElementCached[] Ai = new GroupElementCached[8]; /* A, 3A, 5A, 7A, 9A, 11A, 13A, 15A */ // ge_dsmp type is array of 8 GroupElementCached

        ge_dsm_precomp(Ai, ref A);
        ge_double_scalarmult_precomp_vartime2(out r, a, Ai, b, Bi);

    }

    public static void ge_double_scalarmult_precomp_vartime2(out GroupElementP2 r, byte[] a, GroupElementCached[] Ai, byte[] b, GroupElementCached[] Bi)
    {
        sbyte[] aslide = new sbyte[256];
        sbyte[] bslide = new sbyte[256];
        GroupElementP1P1 t;
        GroupElementP3 u;
        int i;

        GroupOperations.slide(aslide, a);
        GroupOperations.slide(bslide, b);

        GroupOperations.ge_p2_0(out r);

        for (i = 255; i >= 0; --i)
        {
            if (aslide[i] != 0 || bslide[i] != 0)
                break;
        }

        for (; i >= 0; --i)
        {
            GroupOperations.ge_p2_dbl(out t, ref r);

            if (aslide[i] > 0)
            {
                GroupOperations.ge_p1p1_to_p3(out u, ref t);
                GroupOperations.ge_add(out t, ref u, ref Ai[aslide[i] / 2]);
            }
            else
            if (aslide[i] < 0)
            {
                GroupOperations.ge_p1p1_to_p3(out u, ref t);
                GroupOperations.ge_sub(out t, ref u, ref Ai[(-aslide[i]) / 2]);
            }

            if (bslide[i] > 0)
            {
                GroupOperations.ge_p1p1_to_p3(out u, ref t);
                GroupOperations.ge_add(out t, ref u, ref Bi[bslide[i] / 2]);
            }
            else if (bslide[i] < 0)
            {
                GroupOperations.ge_p1p1_to_p3(out u, ref t);
                GroupOperations.ge_sub(out t, ref u, ref Bi[(-bslide[i]) / 2]);
            }

            GroupOperations.ge_p1p1_to_p2(out r, ref t);
  }
}

}

