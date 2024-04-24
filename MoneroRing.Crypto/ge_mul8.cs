using MoneroSharp.NaCl.Internal.Ed25519Ref10;

namespace MoneroRing.Crypto;

public static partial class RingSig
{
	public static void ge_mul8(out GroupElementP1P1 r, ref GroupElementP2 t)
	{
        GroupElementP2 u;
        GroupOperations.ge_p2_dbl(out r, ref t);
        GroupOperations.ge_p1p1_to_p2(out u, ref r);
        GroupOperations.ge_p2_dbl(out r, ref u);
        GroupOperations.ge_p1p1_to_p2(out u, ref r);
        GroupOperations.ge_p2_dbl(out r, ref u);
    }

}

