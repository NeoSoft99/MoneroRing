
using MoneroSharp.NaCl.Internal.Ed25519Ref10;

namespace MoneroRing.Crypto;

public static partial class RingSig
{
    // generates shared secret (derivation)
    public static bool generate_key_derivation(
        byte[] pub_key1, 
        byte[] sec_key2, 
        byte[] derivation)
    {
        GroupElementP3 point;
        GroupElementP2 point2;
        GroupElementP1P1 point3;
        if (sc_check(sec_key2) != 0)
            local_abort("invalid private key");
        
        if (ge_frombytes_vartime(out point, pub_key1) != 0)
        {
            return false;
        }

        ge_scalarmult(out point2, sec_key2, ref point);
        ge_mul8(out point3, ref point2);
        GroupOperations.ge_p1p1_to_p2(out point2, ref point3);
        GroupOperations.ge_tobytes(derivation, 0, ref point2);
        return true;
    }
}

/*bool crypto_ops::generate_key_derivation(const public_key &key1, const secret_key &key2, key_derivation &derivation) {
    ge_p3 point;
    ge_p2 point2;
    ge_p1p1 point3;
    assert(sc_check(&key2) == 0);
    if (ge_frombytes_vartime(&point, &key1) != 0) {
        return false;
    }
    ge_scalarmult(&point2, &unwrap(key2), &point);
    ge_mul8(&point3, &point2);
    ge_p1p1_to_p2(&point2, &point3);
    ge_tobytes(&derivation, &point2);
    return true;
}*/