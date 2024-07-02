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

public class UnitTest_generate_mnemonic_seed
{
    [Fact]
    public void GenerateMnemonicSeed_NullInput_ReturnsFalse()
    {
        byte[] initialSeedBytes = null;
        bool result = RingSig.generate_mnemonic_seed(initialSeedBytes, out byte[] mnemonicSeedBytes);
        Assert.False(result, "Expected false when seedBytes is null.");
        Assert.Null(mnemonicSeedBytes);
    }

    [Fact]
    public void GenerateMnemonicSeed_EmptyInput_ReturnsFalse()
    {
        byte[] initialSeedBytes = new byte[0];
        bool result = RingSig.generate_mnemonic_seed(initialSeedBytes, out byte[]mnemonicSeedBytes);
        Assert.False(result, "Expected false when seedBytes is empty.");
        Assert.Null(mnemonicSeedBytes);
    }
    
    [Fact]
    public void GenerateMnemonicSeed_ShortInput_ReturnsFalse()
    {
        byte[] initialSeedBytes = new byte[31];
        bool result = RingSig.generate_mnemonic_seed(initialSeedBytes, out byte[] mnemonicSeedBytes);
        Assert.False(result, "Expected false when seedBytes is less than 32 bytes");
        Assert.Null(mnemonicSeedBytes);
    }

    [Fact]
    public void GenerateMnemonicSeed_ValidInput_ReturnsTrue()
    {
        byte[] initialSeedBytes = MoneroUtils.HexBytesToBinary(
            "a3858f47f2f4b0aa33a635cb3aaeafc35cffa049b25ea52d41fd0c45fe45123df3e47be148e62ad779fc014f5c1d464aefd906d44c811ab1a1879a1a4da57354");
        bool result = RingSig.generate_mnemonic_seed(initialSeedBytes, out byte[] mnemonicSeedBytes);
        Assert.True(result, "Expected true for a valid seed input.");
        Assert.NotNull(mnemonicSeedBytes);
        Assert.Equal(32, mnemonicSeedBytes.Length);
    }

    [Fact]
    public void GenerateMnemonicSeed_InvalidSeed_ReturnsFalse()
    {
        byte[] initialSeedBytes = MoneroUtils.HexBytesToBinary(
            "f8197a4fecddeac9c7f5172fb244b7d73f5b83e9d485387e15db0ec57471c59ff9ae280c3d8dd9eebc4e87da9c32c63f23a85adb4a80c4d399037a9a145b2a24");
        bool result = RingSig.generate_mnemonic_seed(initialSeedBytes, out byte[] mnemonicSeedBytes);
        Assert.False(result, "Expected false for an invalid seed input.");
        Assert.Null(mnemonicSeedBytes);
    }
}