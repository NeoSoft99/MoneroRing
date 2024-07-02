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
using MoneroSharp.Utils;

namespace MoneroRing.Crypto;

public static partial class RingSig
{
	public static bool check_ring_signature(
         byte[] prefix_hash,
         byte[] image,
         byte[][] pubs,
         int pubs_count,
         //signature[] sig)
         byte[] signature)
    {

        int i;
        GroupElementP3 image_unp;
        GroupElementCached[] image_pre = new GroupElementCached[8]; // ge_dsmp type is array of 8 GroupElementCached

        var sum = new byte[32];

        var buf = new rs_comm(pubs_count);

        if (ge_frombytes_vartime(out image_unp, image) != 0)
            return false;

        RingSignature ring = RingSignature.FromByteArray(signature);
        signature[] sig = ring.sigs;
        
        ge_dsm_precomp(image_pre, ref image_unp);
        sc_0(sum);
        buf.h = prefix_hash;
        for (i = 0; i < pubs_count; i++)
        {
            GroupElementP2 tmp2;
            GroupElementP3 tmp3;
            if (sc_check(sig[i].c) != 0 || sc_check(sig[i].r) != 0)
            {
                //local_abort("invalid signature");
                return false;
            }

            if (ge_frombytes_vartime(out tmp3, pubs[i]) != 0)
            {
                return false;
            }

            ge_double_scalarmult_base_vartime(out tmp2, sig[i].c, ref tmp3, sig[i].r);
            GroupOperations.ge_tobytes(buf.ab[i].a, 0, ref tmp2);
            hash_to_ec(pubs[i], out tmp3);
            ge_double_scalarmult_precomp_vartime(out tmp2, sig[i].r, ref tmp3, sig[i].c, image_pre);
            GroupOperations.ge_tobytes(buf.ab[i].b, 0, ref tmp2);
            sc_add(sum, sum, sig[i].c);
        }
        var h = hash_to_scalar(buf.ToByteArray());
        sc_sub(h, h, sum);
        return sc_isnonzero(h) == 0;
    }

}

