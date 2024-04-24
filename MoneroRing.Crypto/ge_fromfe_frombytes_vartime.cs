using System.Runtime.Intrinsics.X86;
using MoneroSharp.NaCl.Internal.Ed25519Ref10;

namespace MoneroRing.Crypto;

public static partial class RingSig
{
    static FieldElement fe_fffb1 = new FieldElement(-31702527, -2466483, -26106795, -12203692, -12169197, -321052, 14850977, -10296299, -16929438, -407568); /* sqrt(-2 * A * (A + 2)) */
    static FieldElement fe_fffb2 = new FieldElement(8166131, -6741800, -17040804, 3154616, 21461005, 1466302, -30876704, -6368709, 10503587, -13363080); /* sqrt(2 * A * (A + 2)) */
    static FieldElement fe_fffb3 = new FieldElement(-13620103, 14639558, 4532995, 7679154, 16815101, -15883539, -22863840, -14813421, 13716513, -6477756); /* sqrt(-sqrt(-1) * A * (A + 2)) */
    static FieldElement fe_fffb4 = new FieldElement(-21786234, -12173074, 21573800, 4524538, -4645904, 16204591, 8012863, -8444712, 3212926, 6885324); /* sqrt(sqrt(-1) * A * (A + 2)) */

    static FieldElement fe_ma2 = new FieldElement(-12721188, -3529, 0, 0, 0, 0, 0, 0, 0, 0); /* -A^2 */
    static FieldElement fe_ma = new FieldElement(-486662, 0, 0, 0, 0, 0, 0, 0, 0, 0); /* -A */

    static FieldElement fe_sqrtm1 = new FieldElement(-32595792, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654, 326686, 11406482); /* sqrt(-1) */


    //void ge_fromfe_frombytes_vartime(ge_p2* r, const unsigned char* s)
    public static void ge_fromfe_frombytes_vartime(out GroupElementP2 r, byte[] data)
    {
        FieldElement u, v, w, x, y, z;
        int sign;

        // from FieldOperations.fe_frombytes

        var h0 = load_4(data, 0);
        var h1 = load_3(data, 0 + 4) << 6;
        var h2 = load_3(data, 0 + 7) << 5;
        var h3 = load_3(data, 0 + 10) << 3;
        var h4 = load_3(data, 0 + 13) << 2;
        var h5 = load_4(data, 0 + 16);
        var h6 = load_3(data, 0 + 20) << 7;
        var h7 = load_3(data, 0 + 23) << 5;
        var h8 = load_3(data, 0 + 26) << 4;
        var h9 = load_3(data, 0 + 29) << 2;

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

        u.x0 = (int)h0;
        u.x1 = (int)h1;
        u.x2 = (int)h2;
        u.x3 = (int)h3;
        u.x4 = (int)h4;
        u.x5 = (int)h5;
        u.x6 = (int)h6;
        u.x7 = (int)h7;
        u.x8 = (int)h8;
        u.x9 = (int)h9;

        // end of FieldOperations.fe_frombytes

        FieldOperations.fe_sq2(out v, ref u);
        FieldOperations.fe_1(out w);
        FieldOperations.fe_add(out w, ref v, ref w);
        FieldOperations.fe_sq(out x, ref w);

        FieldOperations.fe_mul(out y, ref fe_ma2, ref v);
        FieldOperations.fe_add(out x, ref x, ref y);
        fe_divpowm1(out r.X, ref w, ref x);

        FieldOperations.fe_sq(out y, ref r.X);
        FieldOperations.fe_mul(out x, ref y, ref x);
        FieldOperations.fe_sub(out y, ref w, ref x);
        fe_copy(out z, ref fe_ma);

        if (FieldOperations.fe_isnonzero(ref y) != 0)
        {
            FieldOperations.fe_add(out y, ref w, ref x);
            if (FieldOperations.fe_isnonzero(ref y) != 0)
            {
                goto negative;
            }
            else
            {
                FieldOperations.fe_mul(out r.X, ref r.X, ref fe_fffb1);
            }
        }
        else
        {
            FieldOperations.fe_mul(out r.X, ref r.X, ref fe_fffb2);
        }
        FieldOperations.fe_mul(out r.X, ref r.X, ref u); /* u * sqrt(2 * A * (A + 2) * w / x) */
        FieldOperations.fe_mul(out z, ref z, ref v); /* -2 * A * u^2 */
        sign = 0;
        goto setsign;

    negative:
        FieldOperations.fe_mul(out x, ref x, ref fe_sqrtm1);
        FieldOperations.fe_sub(out y, ref w, ref x);
        if (FieldOperations.fe_isnonzero(ref y) != 0)
        {
            //assert((fe_add(y, w, x), !(FieldOperations.fe_isnonzero(ref y) != 0)));
            FieldOperations.fe_add(out y, ref w, ref x);
            var is_non_zero = FieldOperations.fe_isnonzero(ref y) != 0;
            if (is_non_zero)
                local_abort("y is non zero ");
            FieldOperations.fe_mul(out r.X, ref r.X, ref fe_fffb3);
        }
        else
        {
            FieldOperations.fe_mul(out r.X, ref r.X, ref fe_fffb4);
        }
        /* r->X = sqrt(A * (A + 2) * w / x) */
        /* z = -A */
        sign = 1;

    setsign:
        if (FieldOperations.fe_isnegative(ref r.X) != sign)
        {
            //assert(fe_isnonzero(r->X));
            if (FieldOperations.fe_isnonzero(ref r.X) == 0)
                local_abort("r is zero ");
            FieldOperations.fe_neg(out r.X, ref r.X);
        }
        FieldOperations.fe_add(out r.Z, ref z, ref w);
        FieldOperations.fe_sub(out r.Y, ref z, ref w);
        FieldOperations.fe_mul(out r.X, ref r.X, ref r.Z);

    } 

}
