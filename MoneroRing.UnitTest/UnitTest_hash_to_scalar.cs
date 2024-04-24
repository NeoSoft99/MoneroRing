using MoneroRing.Crypto;
using MoneroSharp.Utils;

namespace MoneroRing.UnitTest;

public class UnitTest_hash_to_scalar
{
    const string key_hex = "da66e9ba613919dec28ef367a125bb310d6d83fb9052e71034164b6dc4f392d0";
    const string expected_res_hex = "52b3f38753b4e13b74624862e253072cf12f745d43fcfafbe8c217701a6e5875";


    byte[] key = MoneroUtils.HexBytesToBinary(key_hex);
    byte[] expected_res = MoneroUtils.HexBytesToBinary(expected_res_hex);

    [Theory]
    [InlineData("59d28aeade98016722948bf596af0b7deb5dd641f1aa2a906bd4e1", "7d0b25809fc4032a81dd5b0f721a2b21f7f68157c834374f580876f5d91f7409")]
    [InlineData("60d9a4b96951481ab458", "b0955682b297dbcae4a5c1b6f21addb211d6180632b538472045b5d592c38109")]
    [InlineData("7d535b4896ddc350a5fdff", "7bb1a59783be93ada537801f31ef52b0d2ea135a084c47cbad9a7c6b0d2c990f")]
    [InlineData("14b5ff33", "709162ee2552c852ba62d406efd369d65851777152c9df4b61a2c4e19190c408")]
    [InlineData("383b76f631652889a182f308b18ddc4e405ba9a9cba5c01b", "36ddbd71a4c19db5ea7022571a52f5a9abe33fc00aafd24b562fb75b7fc0360b")]
    [InlineData("3a170545e462830baf", "c381ea27500b61d29e9ad27add0168053cc1a5b7fc58b6960f67c147324acb03")]
    [InlineData("190757c55bc7", "357f141395a76e2fd5003045b75f3216294eab0524eda1ed16cbe558145a2403")]
    [InlineData("e1dec4027ccb5bf7d273163b316a86", "b365e89545402d3e7d649987127980ec8339af2e3067ff942e305a9ac0b7390d")]
    [InlineData("0b6a0ae839214674e9b275aa1986c6352ec7ec6c4ae583ab5a62b947a9dee972", "24f9167e1a3eaab18119c225577f0ecc7a488a309e54e2721cbaea62c3db3a06")]
    [InlineData("232849cfbb61443dcb681b727cdf7a2b84116dfb74a3c1f935", "8af86aa2f8739b7d384e8431bd1ec5a75a1e7d1dc67f2f7100aeffbaa516200e")]
    public void GenerateKeyImage_CorrectlyConvertsHashToECPoint(string data_hex, string expected_result_hex)
    {
        //byte[] res = new byte[32];
        byte[] data = MoneroUtils.HexBytesToBinary(data_hex);
        byte[] expected_result = MoneroUtils.HexBytesToBinary(expected_result_hex);

        var res = RingSig.hash_to_scalar(data);

        Assert.Equal(expected_result, res);
    }

}
