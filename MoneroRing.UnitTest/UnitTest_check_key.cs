/*
 * MoneroRing, C# .NET implementation of Monero keys, signatures, ring signatures, and key images
 * Github: https://github.com/MystSafe/MoneroRing
 * 
 * Copyright (C) 2024, MystSafe (https://mystsafe.com)
 * Copyright (C) 2024, Author: crypticana <crypticana@proton.me>
 * MystSafe is the only privacy preserving password manager
 *
 * Licensed under MIT (See LICENSE file)
 */

using MoneroRing.Crypto;
using MoneroSharp.Utils;

namespace MoneroRing.UnitTest;

public class UnitTest_check_key
{
    const string key_hex = "c2cb3cf3840aa9893e00ec77093d3d44dba7da840b51c48462072d58d8efd183";

    byte[] key = MoneroUtils.HexBytesToBinary(key_hex);

    [Fact]
    public void GenerateKeyImage_CorrectlyConvertsHashToECPoint()
    {

        bool res = RingSig.check_key(key);

        Assert.False(res);
    }

    [Theory]
    [InlineData("c2cb3cf3840aa9893e00ec77093d3d44dba7da840b51c48462072d58d8efd183", false)]
    [InlineData("bd85a61bae0c101d826cbed54b1290f941d26e70607a07fc6f0ad611eb8f70a6", true)]
    [InlineData("328f81cad4eba24ab2bad7c0e56b1e2e7346e625bcb06ae649aef3ffa0b8bef3", false)]
    [InlineData("6016a5463b9e5a58c3410d3f892b76278883473c3f0b69459172d3de49e85abe", true)]
    [InlineData("4c71282b2add07cdc6898a2622553f1ca4eb851e5cb121181628be5f3814c5b1", false)]
    [InlineData("69393c25c3b50e177f81f20f852dd604e768eb30052e23108b3cfa1a73f2736e", true)]
    [InlineData("3d5a89b676cb84c2be3428d20a660dc6a37cae13912e127888a5132e8bac2163", true)]
    [InlineData("78cd665deb28cebc6208f307734c56fccdf5fa7e2933fadfcdd2b6246e9ae95c", false)]
    [InlineData("e03b2414e260580f86ee294cd4c636a5b153e617f704e81dad248fbf715b2ee4", true)]
    [InlineData("28c3503ce82d7cdc8e0d96c4553bcf0352bbcfc73925495dbe541e7e1df105fc", false)]
    // to do: use all remaining data from tests.txt
    public void CheckKey_ValidatesKeysCorrectly(string keyHex, bool expectedOutcome)
    {

        byte[] key = MoneroUtils.HexBytesToBinary(keyHex);

        bool result = RingSig.check_key(key);

        Assert.Equal(expectedOutcome, result);
    }

}
