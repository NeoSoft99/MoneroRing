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
    public static byte negative(sbyte b)
    {
        var x = unchecked((ulong)b); /* 18446744073709551361..18446744073709551615: yes; 0..255: no */
        x >>= 63; /* 1: yes; 0: no */
        return (byte)x;
    }

    public static void ge_cached_0(out GroupElementCached r)
    {
        FieldOperations.fe_1(out r.YplusX);
        FieldOperations.fe_1(out r.YminusX);
        FieldOperations.fe_1(out r.Z);
        FieldOperations.fe_0(out r.T2d);
    }

    public static void ge_cached_cmov(ref GroupElementCached t, ref GroupElementCached u, byte b)
    {
        FieldOperations.fe_cmov(ref t.YplusX, ref u.YplusX, b);
        FieldOperations.fe_cmov(ref t.YminusX, ref u.YminusX, b);
        FieldOperations.fe_cmov(ref t.Z, ref u.Z, b);
        FieldOperations.fe_cmov(ref t.T2d, ref u.T2d, b);
    }

    public static byte equal(byte b, byte c)
    {

        byte ub = b;
        byte uc = c;
        byte x = (byte)(ub ^ uc); /* 0: yes; 1..255: no */
        uint y = x; /* 0: yes; 1..255: no */
        unchecked { y -= 1; } /* 4294967295: yes; 0..254: no */
        y >>= 31; /* 1: yes; 0: no */
        return (byte)y;
    }

    //public static void ge_scalarmult(out GroupElementP2 r, ref byte[] a, ref GroupElementP3 A)
    public static void ge_scalarmult(out GroupElementP2 r, byte[] a, ref GroupElementP3 A)
	{
        var e = new sbyte[64];
        int carry, carry2, i;

        GroupElementCached[] Ai = new GroupElementCached[8]; /* 1 * A, 2 * A, ..., 8 * A */
        GroupElementP1P1 t;
        GroupElementP3 u;

        carry = 0; /* 0..1 */
        for (i = 0; i < 31; i++)
        {
            carry += a[i]; /* 0..256 */
            carry2 = (carry + 8) >> 4; /* 0..16 */
            e[2 * i] = (sbyte) (carry - (carry2 << 4)); /* -8..7 */
            carry = (carry2 + 8) >> 4; /* 0..1 */
            e[2 * i + 1] = (sbyte) (carry2 - (carry << 4)); /* -8..7 */
        }
        carry += a[31]; /* 0..128 */
        carry2 = (carry + 8) >> 4; /* 0..8 */
        e[62] = (sbyte) (carry - (carry2 << 4)); /* -8..7 */
        e[63] = (sbyte) carry2; /* 0..8 */

        GroupOperations.ge_p3_to_cached(out Ai[0], ref A);

        for (i = 0; i < 7; i++)
        {
            GroupOperations.ge_add( out t, ref A, ref Ai[i]);
            GroupOperations.ge_p1p1_to_p3(out u, ref t);
            GroupOperations.ge_p3_to_cached(out Ai[i + 1], ref u);
        }

        GroupOperations.ge_p2_0(out r);
        for (i = 63; i >= 0; i--)
        {
            sbyte b = e[i];
            byte bnegative = negative(b);
            byte babs = (byte) (b - (((-bnegative) & b) << 1));
            GroupElementCached cur, minuscur;
            GroupOperations.ge_p2_dbl(out t, ref r);
            GroupOperations.ge_p1p1_to_p2(out r, ref t);
            GroupOperations.ge_p2_dbl(out t, ref r);
            GroupOperations.ge_p1p1_to_p2(out r, ref t);
            GroupOperations.ge_p2_dbl(out t, ref r);
            GroupOperations.ge_p1p1_to_p2(out r, ref t);
            GroupOperations.ge_p2_dbl(out t, ref r);
            GroupOperations.ge_p1p1_to_p3(out u, ref t);
            ge_cached_0(out cur);
            ge_cached_cmov(ref cur, ref Ai[0], equal(babs, 1));
            ge_cached_cmov(ref cur, ref Ai[1], equal(babs, 2));
            ge_cached_cmov(ref cur, ref Ai[2], equal(babs, 3));
            ge_cached_cmov(ref cur, ref Ai[3], equal(babs, 4));
            ge_cached_cmov(ref cur, ref Ai[4], equal(babs, 5));
            ge_cached_cmov(ref cur, ref Ai[5], equal(babs, 6));
            ge_cached_cmov(ref cur, ref Ai[6], equal(babs, 7));
            ge_cached_cmov(ref cur, ref Ai[7], equal(babs, 8));
            fe_copy(out minuscur.YplusX, ref cur.YminusX);
            fe_copy(out minuscur.YminusX, ref cur.YplusX);
            fe_copy(out minuscur.Z, ref cur.Z);
            FieldOperations.fe_neg(out minuscur.T2d, ref cur.T2d);
            ge_cached_cmov(ref cur, ref minuscur, bnegative);
            GroupOperations.ge_add(out t, ref u, ref cur);
            GroupOperations.ge_p1p1_to_p2(out r, ref t);
        }
    }

}

