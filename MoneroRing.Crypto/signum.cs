namespace MoneroRing.Crypto;

public static partial class RingSig
{
    // extracts the sign of a real number,
    static long signum(long a)
    {
        return a > 0 ? 1 : a < 0 ? -1 : 0;
    }

}

