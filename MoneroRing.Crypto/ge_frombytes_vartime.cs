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
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace MoneroRing.Crypto;

public static partial class RingSig
{
    public static FieldElement fe_d = new FieldElement(-10913610, 13857413, -15372611, 6949391, 114729, -8787816, -6275908, -3247719, -18696448, -12055116 ); /* d */

    public static int ge_frombytes_vartime(out GroupElementP3 h, byte[] s)
    {
        FieldElement u, v, vxx, check;

        /* From fe_frombytes.c */
        var h0 = load_4(s, 0);
        var h1 = load_3(s, 0 + 4) << 6;
        var h2 = load_3(s, 0 + 7) << 5;
        var h3 = load_3(s, 0 + 10) << 3;
        var h4 = load_3(s, 0 + 13) << 2;
        var h5 = load_4(s, 0 + 16);
        var h6 = load_3(s, 0 + 20) << 7;
        var h7 = load_3(s, 0 + 23) << 5;
        var h8 = load_3(s, 0 + 26) << 4;
        var h9 = (load_3(s, 0 + 29) & 8388607) << 2;

        /* Validate the number to be canonical */
        if (h9 == 33554428 && h8 == 268435440 && h7 == 536870880 && h6 == 2147483520 &&
          h5 == 4294967295 && h4 == 67108860 && h3 == 134217720 && h2 == 536870880 &&
          h1 == 1073741760 && h0 >= 4294967277)
        {
            h = new GroupElementP3(); // just dummy to satisfy compiler
            return -1;
        }

        var carry9 = (h9 + (1 << 24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;
        var carry1 = (h1 + (1 << 24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
        var carry3 = (h3 + (1 << 24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
        var carry5 = (h5 + (1 << 24)) >> 25; h6 += carry5; h5 -= carry5 << 25;
        var carry7 = (h7 + (1 << 24)) >> 25; h8 += carry7; h7 -= carry7 << 25;

        var carry0 = (h0 + (1 << 25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
        var carry2 = (h2 + (1 << 25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
        var carry4 = (h4 + (1 << 25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
        var carry6 = (h6 + (1 << 25)) >> 26; h7 += carry6; h6 -= carry6 << 26;
        var carry8 = (h8 + (1 << 25)) >> 26; h9 += carry8; h8 -= carry8 << 26;

        h.Y.x0 = (int)h0;
        h.Y.x1 = (int)h1;
        h.Y.x2 = (int)h2;
        h.Y.x3 = (int)h3;
        h.Y.x4 = (int)h4;
        h.Y.x5 = (int)h5;
        h.Y.x6 = (int)h6;
        h.Y.x7 = (int)h7;
        h.Y.x8 = (int)h8;
        h.Y.x9 = (int)h9;
        /* From fe_frombytes.c */

        FieldOperations.fe_1(out h.Z);
        FieldOperations.fe_sq(out u, ref h.Y);
        FieldOperations.fe_mul(out v, ref u, ref fe_d);
        FieldOperations.fe_sub(out u, ref u, ref h.Z);       /* u = y^2-1 */
        FieldOperations.fe_add(out v, ref v, ref h.Z);       /* v = dy^2+1 */

        fe_divpowm1(out h.X, ref u, ref v); /* x = uv^3(uv^7)^((q-5)/8) */

        FieldOperations.fe_sq(out vxx, ref h.X);
        FieldOperations.fe_mul(out vxx, ref vxx, ref v);
        FieldOperations.fe_sub(out check, ref vxx, ref u);    /* vx^2-u */
        if (FieldOperations.fe_isnonzero(ref check) != 0)
        {
            FieldOperations.fe_add(out check, ref vxx, ref u);  /* vx^2+u */
            if (FieldOperations.fe_isnonzero(ref check) != 0)
            {
                h = new GroupElementP3(); // just dummy to satisfy compiler
                return -1;
            }
            FieldOperations.fe_mul(out h.X, ref h.X, ref fe_sqrtm1);
        }

        if (FieldOperations.fe_isnegative(ref h.X) != (s[31] >> 7))
        {
            /* If x = 0, the sign must be positive */
            if (!(FieldOperations.fe_isnonzero(ref h.X) != 0))
            {
                h = new GroupElementP3(); // just dummy to satisfy compiler
                return -1;
            }
            FieldOperations.fe_neg(out h.X, ref h.X);
        }

        FieldOperations.fe_mul(out h.T, ref h.X, ref h.Y);
        return 0;

    }
}

