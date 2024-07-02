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

public class UnitTest_secret_key_to_public_key
{
    const string sec_hex = "b2f420097cd63cdbdf834d090b1e604f08acf0af5a3827d0887863aaa4cc4406";
    const string expected_pub_hex = "d764c19d6c14280315d81eb8f2fc777582941047918f52f8dcef8225e9c92c52";
    const string wrong_sec_hex =      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";


    byte[] sec = MoneroUtils.PrivateKeyToBytes(sec_hex);
    byte[] expected_pub = MoneroUtils.HexBytesToBinary(expected_pub_hex);
    byte[] wrongSec = MoneroUtils.HexBytesToBinary(wrong_sec_hex);

    [Fact]
    public void secret_key_to_public_key_ReturnsFalse_WithInvalidPrivateKey()
    {

        byte[] pub = new byte[32]; 


        bool actual_result = RingSig.secret_key_to_public_key(wrongSec, pub);
        Assert.False(actual_result);
    }

    [Fact]
    public void secret_key_to_public_key_CorrectlyGeneratesPublicKey()
    {
        byte[] pub = new byte[32];


        bool actual_result = RingSig.secret_key_to_public_key(sec, pub);

        Assert.True(actual_result);
        Assert.Equal(expected_pub, pub);
    }

}
