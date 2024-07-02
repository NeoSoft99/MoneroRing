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

public class UnitTest_Base58
{
    [Fact]
    public void TestMoneroBase58Conversions()
    {
        byte[] input = new byte[32];
        RingSig.random_scalar(input);
        string input_string = MoneroUtils.BytesToHex(input);

        byte[] input_bytes = MoneroSharp.Base58.Encode(input);
       
        
        byte[] output = MoneroSharp.Base58.Decode(input_bytes);
        string output_string = MoneroUtils.BytesToHex(output);
        
        Assert.Equal(input_string, output_string);
    }
    
    [Fact]
    public void TestMoneroBase58VariableLengthConversions()
    {
        for (int i = 1; i <= 1024; i++)
        {
            int length = i;
            byte[] input = new byte[length];
            RingSig.generate_random_bytes(input, length);
            string input_string = MoneroUtils.BytesToHex(input);

            byte[] input_bytes = MoneroSharp.Base58.Encode(input);
            byte[] output = MoneroSharp.Base58.Decode(input_bytes);
            string output_string = MoneroUtils.BytesToHex(output);
            
            Assert.Equal(input_string, output_string);
        }
    }
    
    [Theory]
    [InlineData("12b66991d7d7c685", "48Y3H2eSZ6C")]
    [InlineData("13533d0560f820d7", "4EUjY1B5viS")]
    public void TestCodecsBase58Conversions(string ascii, string expectedBase58)
    {
        byte[] bytes = MoneroUtils.HexBytesToBinary(ascii);
        
        // Convert ASCII to Base58
        byte[] base58Result = MoneroSharp.Base58.Encode(bytes);

        byte[] back_converstion = MoneroSharp.Base58.Decode(base58Result);
        string back_hex = MoneroUtils.BytesToHex(back_converstion);
        Assert.Equal(ascii, back_hex);
    }
    
}