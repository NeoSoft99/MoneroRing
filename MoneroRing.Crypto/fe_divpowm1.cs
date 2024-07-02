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
    public static void fe_divpowm1(out FieldElement r, ref FieldElement u, ref FieldElement v)
    {
        //FieldElement v3, uv7, t0, t1, t2;
        FieldElement v3, uv7, t0;
        //int i;

        FieldOperations.fe_sq(out v3, ref v);
        FieldOperations.fe_mul(out v3, ref v3, ref v); /* v3 = v^3 */
        FieldOperations.fe_sq(out uv7, ref v3);
        FieldOperations.fe_mul(out uv7, ref uv7, ref v);
        FieldOperations.fe_mul(out uv7, ref uv7, ref u); /* uv7 = uv^7 */

        FieldOperations.fe_pow22523(out t0, ref uv7);

        FieldOperations.fe_mul(out t0, ref t0, ref v3);
        FieldOperations.fe_mul(out r, ref t0, ref u); /* u^(m+1)v^(-(m+1)) */



    }
}

