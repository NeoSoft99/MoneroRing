using MoneroSharp.NaCl;
using MoneroSharp.NaCl.Internal.Ed25519Ref10;

namespace MoneroRing.Crypto;

public static partial class RingSig
{

    public static bool check_signature(byte[] prefix_hash, byte[] pub, byte[] sig_bytes)
    {
        signature sig = signature.FromByteArray(sig_bytes);
        GroupElementP2 tmp2;
        GroupElementP3 tmp3;
        byte[] c;
        s_comm buf;
        if (!check_key(pub))
            return false;
        buf.h = prefix_hash;
        buf.key = pub;
        buf.comm = new byte[32];
        
        if (ge_frombytes_vartime(out tmp3, pub) != 0)
        {
            return false;
        }

        if (sc_check(sig.c) != 0 || sc_check(sig.r) != 0 || sc_isnonzero(sig.c) == 0)
        {
            return false;
        }

        ge_double_scalarmult_base_vartime(out tmp2, sig.c, ref tmp3, sig.r);
        GroupOperations.ge_tobytes(buf.comm, 0, ref tmp2);
        byte[] infinity =
            { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        if (CompareArrays(buf.comm, infinity))
            return false;
        c = hash_to_scalar(buf.ToByteArray());
        sc_sub(c, c, sig.c);
        return sc_isnonzero(c) == 0;
    }
    
    public static bool CompareArrays(byte[] array1, byte[] array2)
    {
        if (array1.Length != array2.Length)
            return false;

        for (int i = 0; i < array1.Length; i++)
        {
            if (array1[i] != array2[i])
                return false;
        }
        return true;
    }
}


/*
bool crypto_ops::check_signature(const hash &prefix_hash, const public_key &pub, const signature &sig) {
    ge_p2 tmp2;
    ge_p3 tmp3;
    ec_scalar c;
    s_comm buf;
    assert(check_key(pub));
    buf.h = prefix_hash;
    buf.key = pub;
    if (ge_frombytes_vartime(&tmp3, &pub) != 0) {
        return false;
    }
    if (sc_check(&sig.c) != 0 || sc_check(&sig.r) != 0 || !sc_isnonzero(&sig.c)) {
        return false;
    }
    ge_double_scalarmult_base_vartime(&tmp2, &sig.c, &tmp3, &sig.r);
    ge_tobytes(&buf.comm, &tmp2);
    static const ec_point infinity = {{ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
    if (memcmp(&buf.comm, &infinity, 32) == 0)
        return false;
    hash_to_scalar(&buf, sizeof(s_comm), c);
    sc_sub(&c, &c, &sig.c);
    return sc_isnonzero(&c) == 0;
}
*/
