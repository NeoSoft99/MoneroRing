using MoneroRing.Crypto;
using MoneroSharp.Utils;

namespace MoneroRing.UnitTest;

public class UnitTest_generate_signature
{
    [Theory]
    [InlineData("f63c961bb5086f07773645716d9013a5169590fd7033a3bc9be571c7442c4c98", "b8970905fbeaa1d0fd89659bab506c2f503e60670b7afd1cb56a4dfe8383f38f", "7bb35441e077be8bb8d77d849c926bf1dd0e696c1c83017e648c20513d2d6907")] // test 2539
    [InlineData("2ade1389a860c9249a42e45d32a9fdc29286c8dc0c8ea1216ba786c74517eefc", "aa2521256174ef6566618a6468c7b8a71ce2dca398be2290148b813710d12f7e", "344a6ad0374b6ae8278e3f226d58e8bb2796e89141eb0ac37cff8552b158260e")] // test 2540
    [InlineData("e64074ccd0cfb5b56a89cb07faa1386061fc4853b0b2211d87a7af02bc3fc0fb", "7072faef529d5daf4fb8663574a4ed86a7fa17e5cf10f09190e280500a216738", "d6d77164dd8a1f6859e8a814d2a17367b8a8fcb5e6bdf345d74ad6d70658520a")] // test 2794
    [InlineData("5e91901e800a1959b4ec07a2eeaa3a9b28893029a26e8ef5d13adde490e5df91", "486dfb4904d81b1bdaf865dc07ff71145d1bf8a9e0c160b9c817315f6cb30398", "6a05fa0a97e172c9a8f5d2e24851ce87bb649a46c34b33330ae71d0d24a4e70a")] // test 2541
    public void CorrectlyGeneratesSignature(string prefix_hash_hex, string pub_hex, string sec_hex)
    {
        byte[] prefix_hash = MoneroUtils.HexBytesToBinary(prefix_hash_hex);
        byte[] pub = MoneroUtils.HexBytesToBinary(pub_hex);
        byte[] sec = MoneroUtils.HexBytesToBinary(sec_hex);
        
        byte[] actual_sig = RingSig.generate_signature(prefix_hash, pub, sec);

        bool check_result = RingSig.check_signature(prefix_hash, pub, actual_sig);
        Assert.True(check_result);
        
        //modify input
        prefix_hash[0] = 0;
        check_result = RingSig.check_signature(prefix_hash, pub, actual_sig);
        Assert.False(check_result);
    }
    
    [Fact]
    public void RandomlyGeneratesSignature()
    {
        byte[] prefix_hash = new byte[32];
        RingSig.generate_random_bytes(prefix_hash, 32);
        
        byte[] sec = new byte[32];
        byte[] pub = new byte[32];
        RingSig.generate_keys(pub, sec);
        
        byte[] sig = RingSig.generate_signature(prefix_hash, pub, sec);

        bool check_result = RingSig.check_signature(prefix_hash, pub, sig);
        Assert.True(check_result);
    }
    
   
}