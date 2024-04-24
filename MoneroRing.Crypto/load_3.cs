namespace MoneroRing.Crypto;

public static partial class RingSig
{
    static long load_3(byte[] input, int offset)
    {
        long result;
        result = (long)input[offset + 0];
        result |= ((long)input[offset + 1]) << 8;
        result |= ((long)input[offset + 2]) << 16;
        return result;
    }
}
