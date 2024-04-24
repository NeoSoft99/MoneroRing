using MoneroSharp.NaCl.Internal.Ed25519Ref10;

namespace MoneroRing.Crypto;

public static partial class RingSig
{
    public static bool check_key(byte[] key)
    {
        GroupElementP3 point;
        return ge_frombytes_vartime(out point, key) == 0;
    }

}

