using MoneroRing.Crypto;
using MoneroSharp.Utils;

namespace MoneroRing.UnitTest;

public class UnitTest_generate_mnemonic_seed
{
    [Fact]
    public void GenerateMnemonicSeed_NullInput_ReturnsFalse()
    {
        byte[] seedBytes = null;
        bool result = RingSig.generate_mnemonic_seed(seedBytes);
        Assert.False(result, "Expected false when seedBytes is null.");
    }

    [Fact]
    public void GenerateMnemonicSeed_EmptyInput_ReturnsFalse()
    {
        byte[] seedBytes = new byte[0];
        bool result = RingSig.generate_mnemonic_seed(seedBytes);
        Assert.False(result, "Expected false when seedBytes is empty.");
    }
    
    [Fact]
    public void GenerateMnemonicSeed_ShortInput_ReturnsFalse()
    {
        byte[] seedBytes = new byte[31];
        bool result = RingSig.generate_mnemonic_seed(seedBytes);
        Assert.False(result, "Expected false when seedBytes is less than 32 bytes");
    }

    [Fact]
    public void GenerateMnemonicSeed_ValidInput_ReturnsTrue()
    {
        byte[] seedBytes = MoneroUtils.HexBytesToBinary(
            "a3858f47f2f4b0aa33a635cb3aaeafc35cffa049b25ea52d41fd0c45fe45123df3e47be148e62ad779fc014f5c1d464aefd906d44c811ab1a1879a1a4da57354");
        bool result = RingSig.generate_mnemonic_seed(seedBytes);
        Assert.True(result, "Expected true for a valid seed input.");
    }

    [Fact]
    public void GenerateMnemonicSeed_InvalidSeed_ReturnsFalse()
    {
        byte[] seedBytes = MoneroUtils.HexBytesToBinary(
            "f8197a4fecddeac9c7f5172fb244b7d73f5b83e9d485387e15db0ec57471c59ff9ae280c3d8dd9eebc4e87da9c32c63f23a85adb4a80c4d399037a9a145b2a24");
        bool result = RingSig.generate_mnemonic_seed(seedBytes);
        Assert.False(result, "Expected false for an invalid seed input.");
    }
}