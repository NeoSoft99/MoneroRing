/*
 * MoneroRing, C# .NET implementation of Monero keys, signatures, ring signatures, and key images
 * Github: https://github.com/MystSafe/MoneroRing
 * 
 * Copyright (C) 2024, MystSafe (https://mystsafe.com)
 * Copyright (C) 2024, Author: crypticana <crypticana@proton.me> 
 * MystSafe is the only privacy preserving password manager
 * Licensed under MIT (See LICENSE file)
 */

using MoneroRing.Crypto;
using MoneroSharp.Utils;

namespace MoneroRing.UnitTest;

public class UnitTest_check_signature
{
    [Theory]
    [InlineData("57fd3427123988a99aae02ce20312b61a88a39692f3462769947467c6e4c3961", "a5e61831eb296ad2b18e4b4b00ec0ff160e30b2834f8d1eda4f28d9656a2ec75", "cd89c4cbb1697ebc641e77fdcd843ff9b2feaf37cfeee078045ef1bb8f0efe0bb5fd0131fbc314121d9c19e046aea55140165441941906a757e574b8b775c008", true)] // test 2795
    [InlineData("92c1259cddde43602eeac1ab825dc12ffc915c9cfe57abcca04c8405df338359", "9fa6c7fd338517c7d45b3693fbc91d4a28cd8cc226c4217f3e2694ae89a6f3dc", "b027582f0d05bacb3ebe4e5f12a8a9d65e987cc1e99b759dca3fee84289efa5124ad37550b985ed4f2db0ab6f44d2ebbc195a7123fd39441d3a57e0f70ecf608", false)] // test 2796
    [InlineData("f8628174b471912e7b51aceecd9373d22824065cee93ff899968819213d338c3", "8a7d608934a96ae5f1f141f8aa45a2f0ba5819ad668b22d6a12ad6e366bbc467", "d7e827fbc168a81b401be58c919b7bcf2d7934fe10da6082970a1eb9d98ca609c660855ae5617aeed466c5fd832daa405ee83aef69f0c2661bfa7edf91ca6201", true)] // test 2796
    public void CorrectlyChecksSignature(string prefix_hash_hex, string pub_hex, string sig_hex, bool expected_result)
    {
        byte[] prefix_hash = MoneroUtils.HexBytesToBinary(prefix_hash_hex);
        byte[] pub = MoneroUtils.HexBytesToBinary(pub_hex);
        byte[] sig = MoneroUtils.HexBytesToBinary(sig_hex);
        
        bool actual_result = RingSig.check_signature(prefix_hash, pub, sig);
        Assert.True(expected_result == actual_result);
    }
}