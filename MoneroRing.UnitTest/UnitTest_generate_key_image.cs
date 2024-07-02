using MoneroRing.Crypto;
using MoneroSharp.Utils;
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

namespace MoneroRing.UnitTest;

public class UnitTest_generate_key_image
{
    const string pub_hex =            "e46b60ebfe610b8ba761032018471e5719bb77ea1cd945475c4a4abe7224bfd0";
    const string sec_hex =            "981d477fb18897fa1f784c89721a9d600bf283f06b89cb018a077f41dcefef0f";
    const string expected_image_hex = "a637203ec41eab772532d30420eac80612fce8e44f1758bc7e2cb1bdda815887";
    const string wrong_sec_hex =      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";



    byte[] pub = MoneroUtils.HexBytesToBinary(pub_hex);
    byte[] sec = MoneroUtils.HexBytesToBinary(sec_hex);
    byte[] expectedImage = MoneroUtils.HexBytesToBinary(expected_image_hex);
    byte[] wrongSec = MoneroUtils.HexBytesToBinary(wrong_sec_hex);

    [Fact]
    public void GenerateKeyImage_ThrowsException_WithInvalidPrivateKey()
    {

        byte[] image = new byte[32]; 


        var ex = Assert.Throws<Exception>(() => RingSig.generate_key_image(pub, wrongSec, image));
        Assert.Equal("invalid private key", ex.Message);
    }

    [Fact]
    public void GenerateKeyImage_CorrectlyGeneratesImage_WithValidKeys()
    {
        byte[] image = new byte[32];


        RingSig.generate_key_image(pub, sec, image);

        Assert.Equal(expectedImage, image);
    }

}
