
using Org.BouncyCastle.Security;

namespace MoneroRing.Crypto;


public static partial class RingSig
{
    public static void generate_random_bytes(byte[] random_bytes, int length_bytes)
    {
        if (random_bytes == null || random_bytes.Length == 0 || random_bytes.Length != length_bytes)
            throw new Exception("Incorrect random buffer size");
        SecureRandom random = new SecureRandom();
        random.NextBytes(random_bytes);
    }

    public static void random_scalar(byte[] data)
    {
        random32_unbiased(data);
    }

    // checks if k0 is less than k1
    static bool less32(byte[] k0, byte[] k1)
    {
        for (int n = 31; n >= 0; --n)
        {
            if (k0[n] < k1[n])
                return true;
            if (k0[n] > k1[n])
                return false;
        }
        return false;
    }

    // l = 2^252 + 27742317777372353535851937790883648493.
    // l fits 15 times in 32 bytes (iow, 15 l is the highest multiple of l that fits in 32 bytes)
    static readonly byte[] limit = new byte[] {
    0xe3, 0x6a, 0x67, 0x72, 0x8b, 0xce, 0x13, 0x29,
    0x8f, 0x30, 0x82, 0x8c, 0x0b, 0xa4, 0x10, 0x39,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0
    };

    static void random32_unbiased(byte[] bytes)
    {
        while (true)
        {
            generate_random_bytes(bytes, 32);
            if (!less32(bytes, limit))
                continue;
            sc_reduce32(bytes);
            if (sc_isnonzero(bytes) != 0)
                break;
        }
    }

}

