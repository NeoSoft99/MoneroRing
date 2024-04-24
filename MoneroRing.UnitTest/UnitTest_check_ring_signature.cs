using MoneroRing.Crypto;
using MoneroSharp.Utils;

namespace MoneroRing.UnitTest;

public class UnitTest_check_ring_signature
{


    
    [Theory]
    //[InlineData("", "", 1, "", "", true)] // test
    [InlineData("c70652ca5f06255dc529bc0924491754f5fad28552f4c9cd7e396f1582cecdca", "89d2e649616ccdf1680e0a3f316dcbd59f0c7f20eba96e86500aa68f123f9ecd", 1, "9cc7f48f7a41d634397102d46b71dd46e6accd6465b903cb83e1c2cd0c41744e", "3e292a748b8814564f4f393b6c4bd2eaaface741b37fd7ac39c06ab41f1b700db548462601351a1226e8247fea67df6f49ea8f7d952a66b9ec9456a99ce7b90b", true)] // test 
    [InlineData("2684f8e51861f569c0fe97f9ba96bc915133016bf9c4b5d78e2a5a25e53d4bd6", "cd2f86eac697799c1107d4cf6fbd6ce5ec933bf164e2fea94208b1b18a032492", 1, "3139d08878da018064cb874eb23c49bbd3e9fe05019f03e0ddd168e6f9c4ef83", "4eb9183536540da0c2cd9068201879cf18348f7f18f2d30816266ecaa9e491fc2dbbe38df202a9426090d6aacd182d06fc8a79f2bf7416188b6648c1fa90bb0c", false)] // test
    [InlineData("2220a2888b6ffdc3c0967d27127205ba4ad99f57c7e36d6a4f65a275d53f5c6e", "4fe553645eea8feb25e52617255cbc98198aefe5fc8afe3a696f3c5848393bf1", 1, "a7b8f77674d544d7e7738c47de264190d460ef274b1308964d3466859c9606ae", "ef44845001fcaebd9217dcf97864f78e27b4af78b41970fb706194ab3b8904870e77951881df0ea748aa91e12dac74be272f2333ab6d4b9ef0b5f06ecdb4450a", false)] // test
    public void Check_Ring_With_1_Key(string prefix_hash_hex, string image_hex, int pubs_count, string pub_0_hex, string signature_hex, bool expected_result)
    {
        byte[] prefix_hash = MoneroUtils.HexBytesToBinary(prefix_hash_hex);
        byte[] image = MoneroUtils.HexBytesToBinary(image_hex);
        byte[] pub_0 = MoneroUtils.HexBytesToBinary(pub_0_hex);
        byte[] signature = MoneroUtils.HexBytesToBinary(signature_hex);

        var pubs = new byte[1][];
        pubs[0] = pub_0;

        bool check_result = RingSig.check_ring_signature(prefix_hash, image, pubs, pubs_count, signature);

        Assert.Equal(expected_result, check_result);
    }

    [Theory]
    //[InlineData("", "", 2, "", "", "", true)] // test
    [InlineData("90660b84dd3be5705c7766695fec404348af6df58f8c5d58213f3b70b8b67a23", "6289b9b151eeb263fc29e4b5e90978db7670f06f408403c8973bbfff2a884dd9", 2, "4af96f2c3a70ac1860d48132136989c1d38551367025d43f36aec0ffa8e7f28a", "376cc178d8ae3a68ce467bfbe719e88b22514617dbd1e764e0b94b4f6bc961af", "4ccadd504d1d03e385ebd25dc51b98c6f3a0e1c1be7e5694e44dc2377898510ca3202d7872294cc04b65d8c109e3a6e843c327b3416ca3a2b1c585fe4152260555441dd7b1543549f749acf5fc9a93a3f3c240425c5f7cadccdef4f06cef0702ae4ad477d0cb60a1a48c1da22f5a8b20c7c5672833c7ae13f78edeb3db1a7b01", true)] // test
    [InlineData("d280b24c280daade9d2bcd68c6dfd39d3a13eb1b0645c4f7d2b0613dd4b5af3d", "f1b943daa1ef225726215f551dfd85f56a3b429ded8608a09a8310a90b8aa88a", 2, "2d4e494897c24b1730f018df65468c2647b2dc19f650d1a9e055b9319045ff13", "74db9c16b0cb4beb7d48ec77b654c63917529072aa57d381b5e3b8dbb06e0f5b", "8aae0a8523d65b3746c87994e4cffaf437ac147a82efe34389d270a976183006c7de37ef0362e13aab9287a85445748a8e0e1a357c6a0ba090f436937a1878b47b41de38a3737152453ca3c0c6546b65ceaff3298329273b0808d35af376a20c1217c85b153d40bc154108eca199175b3efa3f190740325c734d82cfb054d50f", false)] // test
    public void Check_Ring_With_2_Keys(string prefix_hash_hex, string image_hex, int pubs_count, string pub_0_hex, string pub_1_hex, string signature_hex, bool expected_result)
    {
        byte[] prefix_hash = MoneroUtils.HexBytesToBinary(prefix_hash_hex);
        byte[] image = MoneroUtils.HexBytesToBinary(image_hex);
        byte[] pub_0 = MoneroUtils.HexBytesToBinary(pub_0_hex);
        byte[] pub_1 = MoneroUtils.HexBytesToBinary(pub_1_hex);
        byte[] signature = MoneroUtils.HexBytesToBinary(signature_hex);

        var pubs = new byte[2][];
        pubs[0] = pub_0;
        pubs[1] = pub_1;
        bool check_result = RingSig.check_ring_signature(prefix_hash, image, pubs, pubs_count, signature);

        Assert.Equal(expected_result, check_result);
    }

    [Theory]
    //[InlineData("", "", 3, "", "", "", "", true)] // test
    [InlineData("17e1d8c991803cf0747a66dd16a3c5069afb0f604670b823b675bed5de59d6c5", "81abb2291ae3e208665370f4fe07c1d82d3f8f6a6ccafe7e5fb4819ce1d2f113", 3, "130f844d2ff629d6374653997afec462eceed08648daff08eac4c58b9006e6e4", "f92f7aa2bb9273830b966f71c7d7aa0ee8473973d65fa044c74ec4d4628d765c", "8c1f5b3b71c27ebdfadefed2594ba57b19934eda6fb7b5c7e63dd0ed471b6e2e", "7e799950f135343936af6719ebcedfe6e4a3fceaa86047923f592e1fb69aa909575174936ecf6615813c0a4620aa77161d8309aefffd6d33b8eb31b37aa36109dceafe0b8b49a5a280561b204f71f1c6116053ed1bac94b26fcad0ec947a9b01e4459a956e4644f7a8c39719164a87c93d21971366e66e0409556fc93c4c1d0f7db9b2d221fdf6fae05cca363b5e9ea1a7c9b0c80080b9c825f9bcc0b734030711b981b71f0c193bdf51b41bdca81579144e1d7ea134b93a6ba40bd18bb74f07", true)] // test
    [InlineData("5ff6eeadace07009b06de18a7b1f1a52bab052f0f12ca1a309f1b3a2a41eab68", "716e8578ee13828a4eeef26be96ffcddf3778e490ab1544d16dc5b2ea4a7eaa9", 3, "acd7be5c5516a435cccaa23ec5ed35243d68eb1ce6178d34bf11ddbfc42a42b1", "153363bfb53b82d9c00e0d4bfc39ecfd8c9b4303ebc02dfdd8b0ce28835f699c", "07c037a68d8956bf6a88daa7282f2432bf2458ab5e0cbc5a4a88f0f9a1803b2e", "0ac4136c8ee9761504b4b397f03fd440f05b92dd0252db0c95adb545c41f1d0c2b3d7a9460cf3e8ec61fc52cfc31672c9a03b5c77cde0cc17b8c11526f71700b79f8ce45a5e459a401a126947935d8064eabe59a00f8802709bcf66d2ab2b405d3c62629c91017daa20d9b5799d7ac9902305a63122da21f57f944573d3f8d08f574e868e28fb449611c2def05438ff08272be2e9b182c3a7972bd7a1faec50887ae8d13eabffbc3dcc9d2381711860d482f6644d7a22531775f18a7e894a20e", true)] // test
    public void Check_Ring_With_3_Keys(string prefix_hash_hex, string image_hex, int pubs_count, string pub_0_hex, string pub_1_hex, string pub_2_hex, string signature_hex, bool expected_result)
    {
        byte[] prefix_hash = MoneroUtils.HexBytesToBinary(prefix_hash_hex);
        byte[] image = MoneroUtils.HexBytesToBinary(image_hex);
        byte[] pub_0 = MoneroUtils.HexBytesToBinary(pub_0_hex);
        byte[] pub_1 = MoneroUtils.HexBytesToBinary(pub_1_hex);
        byte[] pub_2 = MoneroUtils.HexBytesToBinary(pub_2_hex);
        byte[] signature = MoneroUtils.HexBytesToBinary(signature_hex);

        var pubs = new byte[3][];
        pubs[0] = pub_0;
        pubs[1] = pub_1;
        pubs[2] = pub_2;
        bool check_result = RingSig.check_ring_signature(prefix_hash, image, pubs, pubs_count, signature);

        Assert.Equal(expected_result, check_result);
    }

    [Theory]
    //[InlineData("", "", 4, "", "", "", "", "", true)] // test
    [InlineData("8de9712f7be23bd9a8c5d4c917d82bbf4bb3704b7ffb4e0ac671cbb792b6390d", "5714b726fae39a7e6c5e9958bb46720c8c51247eeba4891934e67dbcd3acb048", 4, "5d3c14d793be0fa1edccf3d7ae1ae320d40116e0206347b8c033682bf2ec2e5a", "51e5fd3255a7b0447c6f1e16fc50596a5002156d6edfb60c2822261b37443c01", "ce959da6cf5b2594ba77a1f164da973fcd718b778b1de072adab957be9609467", "9199bcf6dd5501e06348f48e821e21dcfb7f2aa6b33a47c6ef46774363a0befd", "5fa3d59afe89be2a8b4ea8aead0b3860e5cac8edf0b7b0776de764392d52160c8531d28a5703c139ac2cf4ed8ec06e8dc0f81a4549290b134a5e67a4c80e38088572fd79f042b718cb9939c28c191e3c5091d64cc3ed80244d16e2ec8f180b04523bb3c6e3f232e69b609e9cf66acb49ac65dfe8823fd252beba85e461692709e8f67d4ce840a8397b01698b727df78a0b79929aa84e76c6adf2ed4d20a6ee0540aac64b477deb212e56f28918735268110ac977962749d131481a8d33c49905dc834be581a430e1c3fae7743d004c092803294cadf2385deeff6c80b23ca603ed03b747e22b2832866ee0ad5666ea1bd706f17881d743718cdc82de7da71b03", true)] // test
    [InlineData("f5fe4bc6b950f98ad864f82deb864110f2d395e399b62d9d9b9c89b063c4a535", "c94f2b3388a9bdda02f7a2ca5c1254a6d2fb4e3c611681f83464578df932afc7", 4, "baf7c6e12264853d4ff8376f6cc2e2bcb66aa912577817636b2010f2157d6684", "8bfcef9fc057e42fb1944d16e4942afeeb22ae30b5d890e6a14ac6e7c3ecb1a2", "2adf439f1b090a3072109c77599834eef4159e2de317ed73c057cd1dbbb4195e", "f4c410e8bea7072adda30daec2ac239d8e6294d15add6378c5dd53d0e742c39c", "1a2ac8f6022e4758f4967d458f0c238706c1c27afbe3bcb26c1ba9accd4d71054488e507250e91ebf819af68b93d464cbf1e436b0c71c46cc0adb39628c84a07d698274b398f915bd5636e980edf2786937fccfd89eaa3b7db1a77a63079490ae715c9903754ae604340fcd0b5ec4c8bfdb5edae1a08dec009e853e2a19179069a22c39a0353d983e60bd808d83ab971e0ccef64ada39fa883245390c3eccb00baa37568870e96eae60a611417db31761612509ed2563975c9fd69260793ff053f7a159e2d79d1d0b521003067cd1e4fc7b625b15f4c91b3c7b1290c1e3edb022ad5f42a16c1be85343cdd63e6b94e818f847548c369d17f300aa48bddd45a0e", false)] // test
    public void Check_Ring_With_4_Keys(string prefix_hash_hex, string image_hex, int pubs_count, string pub_0_hex, string pub_1_hex, string pub_2_hex, string pub_3_hex, string signature_hex, bool expected_result)
    {
        byte[] prefix_hash = MoneroUtils.HexBytesToBinary(prefix_hash_hex);
        byte[] image = MoneroUtils.HexBytesToBinary(image_hex);
        byte[] pub_0 = MoneroUtils.HexBytesToBinary(pub_0_hex);
        byte[] pub_1 = MoneroUtils.HexBytesToBinary(pub_1_hex);
        byte[] pub_2 = MoneroUtils.HexBytesToBinary(pub_2_hex);
        byte[] pub_3 = MoneroUtils.HexBytesToBinary(pub_3_hex);
        byte[] signature = MoneroUtils.HexBytesToBinary(signature_hex);

        var pubs = new byte[4][];
        pubs[0] = pub_0;
        pubs[1] = pub_1;
        pubs[2] = pub_2;
        pubs[3] = pub_3;
        bool check_result = RingSig.check_ring_signature(prefix_hash, image, pubs, pubs_count, signature);

        Assert.Equal(expected_result, check_result);
    }

}
