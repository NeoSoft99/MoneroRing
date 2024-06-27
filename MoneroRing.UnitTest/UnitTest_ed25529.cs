/*using MoneroRing.Crypto;
using MoneroSharp.NaCl;
using MoneroSharp.Utils;

namespace MoneroRing.UnitTest;

public class UnitTest_ed25529
{
    [Fact]
    public void SignAndVerifySignatureTest()
    {
        //const string seed_hex = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"; //"7178d4fa3c6aa96c335c30133c0e95fefa1f1fac2905898c018b323888856a0d"; //"b2f420097cd63cdbdf834d090b1e604f08acf0af5a3827d0887863aaa4cc4406";
        const string seed_hex = "7178d4fa3c6aa96c335c30133c0e95fefa1f1fac2905898c018b323888856a0d";
        const string hash_hex = "72"; //"52b3f38753b4e13b74624862e253072cf12f745d43fcfafbe8c217701a6e5875";

        byte[] seed = MoneroUtils.HexBytesToBinary(seed_hex);
        //byte[] pub = new byte[32];
    
        //RingSig.secret_key_to_public_key(sec, pub);
        byte[] pub = Ed25519.PublicKeyFromSeed(seed);
        Console.WriteLine("Public Key: " + MoneroUtils.BytesToHex(pub));

        byte[] expanded_private_key = Ed25519.ExpandedPrivateKeyFromSeed(seed);
        Console.WriteLine("Expanded Private Key: " + MoneroUtils.BytesToHex(expanded_private_key));

        byte[] hash = MoneroUtils.HexBytesToBinary(hash_hex);
        Console.WriteLine("Hash: " + MoneroUtils.BytesToHex(hash));

        byte[] signature_bytes = Ed25519.Sign(hash, expanded_private_key);
        Console.WriteLine("Signature: " + MoneroUtils.BytesToHex(signature_bytes));
        
        Console.WriteLine("Hash: " + MoneroUtils.BytesToHex(hash));
        Console.WriteLine("Public Key: " + MoneroUtils.BytesToHex(pub));
        bool result = Ed25519.Verify(signature_bytes, hash, pub);
        Console.WriteLine("Signature Valid: " + result);

        Assert.True(result);
    }
}*/