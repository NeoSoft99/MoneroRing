using System.Security.Cryptography.X509Certificates;
using System.Text;
using MoneroSharp.NaCl.Internal.Ed25519Ref10;

namespace MoneroRing.Crypto;

public static partial class RingSig
{
    public static void generate_keys(byte[] pub, byte[] sec)
    {
        GroupElementP3 point;
        random_scalar(sec);
        sc_reduce32(sec);
        GroupOperations.ge_scalarmult_base(out point, sec, 0);
        GroupOperations.ge_p3_tobytes(pub, 0, ref point);
    }

}

