
using MoneroSharp.NaCl.Internal.Ed25519Ref10;

namespace MoneroRing.Crypto;

public static partial class RingSig
{
    public static void fe_copy(out FieldElement h, ref FieldElement f)
    {

        int f0 = f.x0;
        int f1 = f.x1;
        int f2 = f.x2;
        int f3 = f.x3;
        int f4 = f.x4;
        int f5 = f.x5;
        int f6 = f.x6;
        int f7 = f.x7;
        int f8 = f.x8;
        int f9 = f.x9;

        h.x0 = f0;
        h.x1 = f1;
        h.x2 = f2;
        h.x3 = f3;
        h.x4 = f4;
        h.x5 = f5;
        h.x6 = f6;
        h.x7 = f7;
        h.x8 = f8;
        h.x9 = f9;
    }
}

