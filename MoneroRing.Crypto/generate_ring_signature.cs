
using MoneroSharp.NaCl.Internal.Ed25519Ref10;

namespace MoneroRing.Crypto;

public static partial class RingSig
{
    public static void local_abort(string abort_message)
    {
        throw new Exception(abort_message);
    }

    public static bool AreEqual(byte[] a1, byte[] a2)
    {
        if (a1 == a2)
            return true;
        if (a1 == null || a2 == null)
            return false;
        if (a1.Length != a2.Length)
            return false;

        for (int i = 0; i < a1.Length; i++)
        {
            if (a1[i] != a2[i])
                return false;
        }
        return true;
    }

    // returns byte[] array containing ring signature
    public static byte[] generate_ring_signature(
                byte[] prefix_hash,
                byte[] image,
                byte[][] pubs,
                int pubs_count,
                byte[] sec,
                int sec_index)
    {

        int i;
        GroupElementP3 image_unp;
        GroupElementCached[] image_pre = new GroupElementCached[8]; // ge_dsmp type is array of 8 GroupElementCached
        signature[] sig = new signature[pubs_count];

        var sum = new byte[32];
        var k = new byte[32];

        var buf = new rs_comm(pubs_count);

        if (sec_index >= pubs_count)
            local_abort("invalid key index");

        // this is DEBUG section in the original cpp code
        GroupElementP3 t;
        byte[] t2 = new byte[32]; // public key
        byte[] t3 = new byte[32]; // key image
        if (sc_check(sec) != 0)
            local_abort("invalid private key");
        GroupOperations.ge_scalarmult_base(out t, sec, 0);
        GroupOperations.ge_p3_tobytes(t2, 0, ref t);
        if (!AreEqual(pubs[sec_index], t2))
            local_abort("invalid public key");
        generate_key_image(pubs[sec_index], sec, t3);
        if (!AreEqual(image, t3))
            local_abort("invalid key image");
        for (i = 0; i < pubs_count; i++)
        {
            if (!check_key(pubs[i]))
                local_abort("invalid public key at index " + i.ToString());
        }

        // end of DEBUG


        if (ge_frombytes_vartime(out image_unp, image) != 0)
            local_abort("invalid key image");
        
        ge_dsm_precomp(image_pre, ref image_unp);
        sc_0(sum);
        buf.h = prefix_hash;
        for (i = 0; i < pubs_count; i++)
        {
            GroupElementP2 tmp2;
            GroupElementP3 tmp3;
            sig[i] = new signature();

            if (i == sec_index)
            {
                random_scalar(k);

                GroupOperations.ge_scalarmult_base(out tmp3, k, 0);
                GroupOperations.ge_p3_tobytes(buf.ab[i].a, 0, ref tmp3);
                hash_to_ec(pubs[i], out tmp3);
                //ge_scalarmult(out tmp2, ref k, ref tmp3);
                ge_scalarmult(out tmp2, k, ref tmp3);
                GroupOperations.ge_tobytes(buf.ab[i].b, 0, ref tmp2);
            }
            else
            {
                random_scalar(sig[i].c);
                random_scalar(sig[i].r);
                if (ge_frombytes_vartime(out tmp3, pubs[i]) != 0)
                {
                    local_abort("invalid pubkey");
                }
                ge_double_scalarmult_base_vartime(out tmp2, sig[i].c, ref tmp3, sig[i].r);
                GroupOperations.ge_tobytes(buf.ab[i].a, 0, ref tmp2);
                hash_to_ec(pubs[i], out tmp3);
                ge_double_scalarmult_precomp_vartime(out tmp2, sig[i].r, ref tmp3, sig[i].c, image_pre);
                GroupOperations.ge_tobytes(buf.ab[i].b, 0, ref tmp2);
                sc_add(sum, sum, sig[i].c);
            }
        }

        var h = hash_to_scalar(buf.ToByteArray());
        sc_sub(sig[sec_index].c, h, sum);
        sc_mulsub(sig[sec_index].r, sig[sec_index].c, sec, k);

        var ring = new RingSignature(sig);

        return ring.ToByteArray();
    }

}

