namespace MoneroRing.Crypto;

public static partial class RingSig
{
    // Converts any random seed of any length to the seed
    // suitable for generating Monero mnemonic. 
    // input (seed_bytes): random seed, any length 
    // output (seed_bytes): Monero mnemonic-compatible seed
    // returns:
    //     true if success; seed_bytes contains modified seed
    //     false if interim_seed is not compatible
    public static bool generate_mnemonic_seed(byte[] seed_bytes)
    {
        if (seed_bytes == null || seed_bytes.Length < 32)
            return false;
        var keccak256 = new Nethereum.Util.Sha3Keccack();
        byte[] interim_seed = keccak256.CalculateHash(seed_bytes);
        if (!less32(interim_seed, limit))
            return false;
        sc_reduce32(interim_seed);
        if (sc_isnonzero(interim_seed) != 0)
            return true;
        return false;
    }
}