
using MoneroSharp.Utils;

namespace MoneroRing.UnitTest;

public class UnitTest_keccak
{
    const string key_hex = "da66e9ba613919dec28ef367a125bb310d6d83fb9052e71034164b6dc4f392d0";
    const string expected_res_hex = "2faaf995b8716034c3c2f6a0dc4842353dcecf2fc20d328ca071225b8ee358d0";


    byte[] key = MoneroUtils.HexBytesToBinary(key_hex);
    byte[] expected_res = MoneroUtils.HexBytesToBinary(expected_res_hex);

    [Fact]
    public void GenerateKeyImage_CorrectlyGenerateKeccak()
    {
        byte[] res = new byte[32];

        var keccak256 = new Nethereum.Util.Sha3Keccack();
        byte[] h = keccak256.CalculateHash(key);

        Assert.Equal(expected_res, h);
    }

}
