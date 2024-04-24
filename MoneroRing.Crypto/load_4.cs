namespace MoneroRing.Crypto;

public static partial class RingSig
{
    static long load_4(byte[] input, int offset)
    {
        long result;
        result = (long)input[offset + 0];
        result |= ((long)input[offset + 1]) << 8;
        result |= ((long)input[offset + 2]) << 16;
        result |= ((long)input[offset + 3]) << 24;
        return result;
    }
}


