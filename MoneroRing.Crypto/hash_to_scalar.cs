namespace MoneroRing.Crypto;

public static partial class RingSig
{
    public static byte[] hash_to_scalar(byte[] data)
    {
        //cn_fast_hash(data, length, reinterpret_cast < hash &> (res));
        var keccak256 = new Nethereum.Util.Sha3Keccack();
        byte[] res = keccak256.CalculateHash(data);

        sc_reduce32(res);
        return res;
    }

}

