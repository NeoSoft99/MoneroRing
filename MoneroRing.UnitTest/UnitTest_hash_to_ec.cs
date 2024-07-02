/*
 * MoneroRing, C# .NET implementation of Monero keys, signatures, ring signatures, and key images
 * Github: https://github.com/MystSafe/MoneroRing
 * 
 * Copyright (C) 2024, MystSafe (https://mystsafe.com)
 * Copyright (C) 2024, Author: crypticana <crypticana@proton.me>
 * 
 * MystSafe is the only privacy preserving password manager
 *
 * Licensed under MIT (See LICENSE file)
 */

using MoneroRing.Crypto;
using MoneroSharp.Utils;

namespace MoneroRing.UnitTest;

public class UnitTest_hash_to_ec
{
    const string key_hex = "";
    const string expected_res_hex = "";


    byte[] key = MoneroUtils.HexBytesToBinary(key_hex);
    byte[] expected_res = MoneroUtils.HexBytesToBinary(expected_res_hex);

    [Theory]
    [InlineData("da66e9ba613919dec28ef367a125bb310d6d83fb9052e71034164b6dc4f392d0", "52b3f38753b4e13b74624862e253072cf12f745d43fcfafbe8c217701a6e5875")]
    [InlineData("a7fbdeeccb597c2d5fdaf2ea2e10cbfcd26b5740903e7f6d46bcbf9a90384fc6", "f055ba2d0d9828ce2e203d9896bfda494d7830e7e3a27fa27d5eaa825a79a19c")]
    [InlineData("ed6e6579368caba2cc4851672972e949c0ee586fee4d6d6a9476d4a908f64070", "da3ceda9a2ef6316bf9272566e6dffd785ac71f57855c0202f422bbb86af4ec0")]
    [InlineData("9ae78e5620f1c4e6b29d03da006869465b3b16dae87ab0a51f4e1b74bc8aa48b", "72d8720da66f797f55fbb7fa538af0b4a4f5930c8289c991472c37dc5ec16853")]
    [InlineData("ab49eb4834d24db7f479753217b763f70604ecb79ed37e6c788528720f424e5b", "45914ba926a1a22c8146459c7f050a51ef5f560f5b74bae436b93a379866e6b8")]
    public void GenerateKeyImage_CorrectlyConvertsHashToECPoint(string key_hex, string expected_result_hex)
    {
        byte[] res = new byte[32];
        byte[] key = MoneroUtils.HexBytesToBinary(key_hex);
        byte[] expected_result = MoneroUtils.HexBytesToBinary(expected_result_hex);

        RingSig.hash_to_ec(key, res);

        Assert.Equal(expected_result, res);
    }

}
