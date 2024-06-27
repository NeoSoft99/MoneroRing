using MoneroRing.Crypto;
using MoneroSharp.Utils;

namespace MoneroRing.UnitTest;

public class UnitTest_generate_ring_signature
{


    
    [Theory]
    [InlineData("3e592f32788ec54e3f10560b1380761329df534096ec12251382a96f8cab7eba", "0b72892038d4248c430d1ac93f4985a8bb9b43fdf457a83618b7045980b8e6a2", 1, "526c98024c9a4fa8c6ccad5101f4afc972fdeb228620d774669c13ec4d029cb7", "0741f944319e0c4678f4a414a12c6956cf9d4b3ad04a40cd6030e47ab7e9700e", 0, "40a91c1d26116109f14783aff31dcf7f3c952a03574a1cac1b52a5daf2f15800a821d84709ce7b60b98899d1d6e224f46ea06355261ce3f85497c2bb37ba0c0a")] // test 4194
    [InlineData("701268c079222197470218f73587bdeb19c3620f25d1511042edabd0efcae448", "c2b7340137942802b68be0a9cd0deb826a43f7645807c8f4179c64b11021c36a", 1, "515cc1cbddabcae11062f52ba676265114a44372719b9b5dcff7865cfbbf1568", "20966d94502e95dffb45bf07173991a5c0ebca48c0941c8c6705f7370bb2340b", 0, "b91d39116f1997fc4282443076de8a36f38f8b60618a3704c3c0a757b06bfc072b2c03e927822ef631248d929ecec10c3a393b5c5eeac3f5217a3edb2972f308")] // test 4195
    //[InlineData("", "", 1, "", "", 0, "")] // test 
    public void CorrectlyGeneratesRing_WithSingleKey(string prefix_hash_hex, string image_hex, int pubs_count, string pub_0_hex, string sec_hex, int sec_index, string expected_signature_hex)
    {
        byte[] prefix_hash = MoneroUtils.HexBytesToBinary(prefix_hash_hex);
        byte[] image = MoneroUtils.HexBytesToBinary(image_hex);
        byte[] pub_0 = MoneroUtils.HexBytesToBinary(pub_0_hex);
        byte[] sec = MoneroUtils.HexBytesToBinary(sec_hex);
        byte[] expected_signature = MoneroUtils.HexBytesToBinary(expected_signature_hex);

        var pubs = new byte[1][];
        pubs[0] = pub_0;
        byte[] sig = RingSig.generate_ring_signature(prefix_hash, image, pubs, pubs_count, sec, sec_index);
        //Assert.Equal(expected_signature, sig);
        
        bool check_result = RingSig.check_ring_signature(prefix_hash, image, pubs, pubs_count, sig);

        Assert.True(check_result);
    }

    [Theory]
    //[InlineData("", "", 2, "", "", "", 0, "")] // test
    [InlineData("89226689e486049662075f55d46361d821c5ede1fc172581458207aeb3d7374b", "4048d63774cf0e3d73059b76c1160f5b36fae2add758c0b5d0a76eccf459081b", 2, "68943d3665e40eaa5d8ce9a3279e70e9d00afa0cea15d6671e024efcdad2900c", "fb89cf7108eb3b68243e732e820d716e11a0baa0def8d2d837ab998a9bd642c0", "f75b48b628a7f3fd1dce1055f7c0b81c36454e012dc7ead8d5528c11cd52990d", 1, "00568f5c1a9423b58a98e734a084d097dd288b63ade91a39844a9d3ca828d5086153b0ea8dea0f853b12579dae0cebad5e5cb47fb1ee2382351c61c689be6d04dd8a4b294dd02e44d30a2b19f7f9d471ac7fc13d69e3bd8bf46ca6435f2ac10c23ddaf8eb6dd1f185445b5125c56c1384806ce63976d16268d4b9472ea850e09")] // test
    [InlineData("e8020add6aebab8ca5f8b49f2072f631745887fa205d8db1a3aa1b5a4e232d81", "dd963b8d2145bd369feed2501aeac1de2fa16ecb1b7cb93564535a6dbccbb3c0", 2, "9f1c652d42539ae6c7a43a5118d5890a4e1b386b3a400ebd8f2dd5687626dd55", "90a86ceb7951f7b5668205c22e8d2c9953d0e44773f7d0159618a8a0238a53b6", "5e6dd5608134fa4c64007aecaa340a0f379d1a5c6d4adbf017a239eba303c808", 0, "cf87c865aded2f353b16cc13299c55e457a9c8b414915a2dcb55f27a2a6d910294a7f99bf5283b2e6ef0e5397343571fde3b8b3d8a982cdaa98a2b8f1073cc067a48eb439c17d011e66708e35f8302d8612af85d4cb941ca4feff430fddef001155c30767941cedda2027618f381cf77a89801f8d8ea38454b9f98a5c330550f")] // test 
    public void CorrectlyGeneratesRing_WithTwoKeys(string prefix_hash_hex, string image_hex, int pubs_count, string pub_0_hex, string pub_1_hex, string sec_hex, int sec_index, string expected_signature_hex)
    {
        byte[] prefix_hash = MoneroUtils.HexBytesToBinary(prefix_hash_hex);
        byte[] image = MoneroUtils.HexBytesToBinary(image_hex);
        byte[] pub_0 = MoneroUtils.HexBytesToBinary(pub_0_hex);
        byte[] pub_1 = MoneroUtils.HexBytesToBinary(pub_1_hex);
        byte[] sec = MoneroUtils.HexBytesToBinary(sec_hex);
        byte[] expected_signature = MoneroUtils.HexBytesToBinary(expected_signature_hex);
        
        var pubs = new byte[2][];
        pubs[0] = pub_0;
        pubs[1] = pub_1;
        byte[] actual_sig = RingSig.generate_ring_signature(prefix_hash, image, pubs, pubs_count, sec, sec_index);
        //Assert.Equal(expected_signature, actual_sig);
        
        bool check_result = RingSig.check_ring_signature(prefix_hash, image, pubs, pubs_count, actual_sig);

        Assert.True(check_result);
    }

    [Theory]
    //[InlineData("", "", 3, "", "", "", "", 0, "")] // test
    [InlineData("d2b1be9c36ccec50df11eb89ccada0a0d065fafc1a4b7296d85180598d0208fb", "790464d130c590b15283bdb524cdc611c1dfe90ed958cfdd1c61f4a8c610e971", 3, "c760502af5bd01024b414aa8e6ec3291d24a119c069e5394023daa44cf502a35", "304177d3c97d2ea31afd6600fab36a15763c2a7d6fd2b179aaf9adf4a6d93288", "5c01ec55a849da5d9c141a1da2cadd189c7cc4302866056619bcf541c0ff4c0b", "67567e52f4f0d0b41c1b633d3ff41eb5a3af5abbb4b71ea61b57dc39e433bd01", 2, "88a87a4b0b732f296480abe26f8227febfc48469b0f25d5f89a23cf2c661fa0d363f0720339f76ef75d0ee7113b966b596c51326fc450d70e44450c6a623820f06991c7c896c7b0091ae83b4a4fc277e1daf6c26bf7b632fd97d8504f6536b0c4a0112c1ed00b9efcd4c088146a13b555c9c682a49a2aae35f0bff031ab07002cfd8c82a94a5a2a7e6748b7b06e4932cc60ad9a2be5df326b947717110beaf080f12333977f45ada91bd96cdf1c2e11a74be53176ec2c2d89a7fd7dec5f58a0b")] // test
    [InlineData("1d0b119ca5e69bfccdec2771ff272dc2c8638c187733438939525ccb8005f4ff", "8645d7285139bdfe550241936b2fc8a26757ffcaa7bac9084ff8a85cebbd1e89", 3, "8a075c4f74b5520b511ee1a487cb31c4cc93befa5af0887414efe0115fbac0cd", "5407168cd81fe9cba6a34e7e30cbca17f448f2226131ea57acd74420675830fc", "2ffe6b476ff37d8d6487cc1c7e5e89ba0295a5d0128e6ecf8ae64165d6d14d84", "ffacc2cc992ccbdc7cb0cc1a695ca31a92f6d6a2563b03349688a63a86f8ed01", 0, "03f26b490203321e05d05fb97cd5798379a13da98f650bc963cc86a423ea8900c66034480e689507183531e0fecf731e3024108e9b3f094c5478119df738870a82278ccaccfe43b2aeb66d58ad9e4d9575f89b1929635cc7824c1210a377850c605c943293f9c15a890d384bf42f03ac233f2d92028b02900f8cafbdfb9d0a06a7f2784c0c2a3df0ed61e9c4c48d570bec77599f3fb3c4cd60d27c0b41f8b10e087e8c4a9119c724a918ebc5638be8c94a0d88151434af46320031bae1886201")] // test
    [InlineData("c9ab4560e364fa2cbf7ec6e3aa25251bcaf2beb043ccacb0a4624058fd88d86a", "5d6b8e078641aea54474ec65784fccb1e95d3a0f6c1b97005d6fb65077c145ac", 3, "56d63e1b1a487fd4d7975e66dc212e3ba4180fcbc6ba777bda12c4a957f359d1", "0ba8218820fc5a47b7449974d27f4cf1fd7ba6698f087a6b007a15637c8c56ca", "eec4a9fdb41c38be9bbb62e86f0d497b8adef1c297306cc3a209a700f1c76981", "461bd2cc07b9c8310b74820b6b7fafb962605dc168cdb11be6995b344bf95305", 1, "793e60045a0e7c7336eba35db6e1597ec5809ade6e1a043bad9713c20f549b04e38197c186524f08eee4faf1d1e8968c4a6c5ed4b2c87a178e64e496d77f4408638b73741b0003eecdd50f7332143dcf0a54f3f14087c1ebad6028da46d19e04e41ae496619b8740142f6b8c352a42085d287b1e14e731fdbe0203b3914cb50cc6718b761eca00d1bc84320e14d81371112ef60045ed6eeee7e0515dea378e0db75ccf8176aa75c7ec237d3ae4004ca8defdc7641bc924dcd33bd12875516506")] // test
    public void CorrectlyGeneratesRing_WithThreeKeys(string prefix_hash_hex, string image_hex, int pubs_count, string pub_0_hex, string pub_1_hex, string pub_2_hex, string sec_hex, int sec_index, string expected_signature_hex)
    {
        byte[] prefix_hash = MoneroUtils.HexBytesToBinary(prefix_hash_hex);
        byte[] image = MoneroUtils.HexBytesToBinary(image_hex);
        byte[] pub_0 = MoneroUtils.HexBytesToBinary(pub_0_hex);
        byte[] pub_1 = MoneroUtils.HexBytesToBinary(pub_1_hex);
        byte[] pub_2 = MoneroUtils.HexBytesToBinary(pub_2_hex);
        byte[] sec = MoneroUtils.HexBytesToBinary(sec_hex);

        var pubs = new byte[3][];
        pubs[0] = pub_0;
        pubs[1] = pub_1;
        pubs[2] = pub_2;
        byte[] sig = RingSig.generate_ring_signature(prefix_hash, image, pubs, pubs_count, sec, sec_index);

        bool check_result = RingSig.check_ring_signature(prefix_hash, image, pubs, pubs_count, sig);

        Assert.True(check_result);
    }

    [Theory]
    //[InlineData("", "", 4, "", "", "", "", "", 0, "")] // test
    [InlineData("1516afdad27c8277ff77ebe9cc6b9889061ab85d504c7678b51d1b453e656f4a", "77eeb7c8666282fa03e473416d2b495c62e9b8423bd30aa054cdac22f0173b75", 4, "294897bcd480edc6eb3f302bec49fa75aa38de4ea0a5b3ce458e284477a4df2f", "d7b3729fc615104085544ea277352df10f43e24e8b7f47469893f34df7197e95", "9e4ab024bd6a82f3544a941c0dd88b2985601df873cfb6c82c669562d0ccb2c1", "768ca9255bad7ce9db858bf51271f6321620424e7e24e5422395b10e3fe48a04", "7328152575f971140847e181482617d1220f0cd933535cbd8a5492e8c857030d", 2, "435e89e3fc34b6a35f9f017e2c91d0405fbe77b99df628be43cebf79361d9909469ddcf9e6729df07da7024731f0d6d1fc35ba29b0fc6e265cf8119801d6c90d64f938eec1fffb3b11a7146f979944170da4223149936e20b2e89eacfeb7130329dc937dcba837e605950f9e441cf7dacecd515f8a3df4920d57559910dffd058251005bb63fc30e9820eda2987c551c89acc5dca4b25d0a96b7749f0916170373b58fea1265bae6050f9c5274bf7becd89c096d1b8ecc874d62eff4829e680b1f94ec7883d39ea6edcb6d63afd8efed2d39e17ac655b81ff63209cc456b3603fa4727205e613fe4f2e09761bd0e2e7fec4acca582a17ef208f250556ea93008")] // test
    [InlineData("953630fc2044cd653f7a0ba4d3413eb62f6e17867d2a24283d65c3ce6318f887", "e901f99a3e172a3f7de853302c9ca5a1ef79f5762c13ae654c4259e8cee66e33", 4, "de453f88739ae0d8339d5176fee305db6c4558ba79cf29f7cd9d578ed6f93f73", "2662a16a5721e8273db4eba161eed7f6c55372ce1b57ffab8347f94ea937ba77", "9b838a770120cd96e91ea3753b6728aa50c8428a6bda2dd55ebb2ace9abefb72", "7555929a6e983390a6d99b9fb21340bdea436104456f7345e6319e772f17fa82", "47baf5064573771c80e48605222461043b10259e4b1d5ab00ee4c5109eaf0509", 0, "c281d8e51da7469a66216c0eb20954e6665d4ba06c3f561252b2a01639e5850a3a1ff8e058e4345b2deade2074a6548d017869550cf1cf0f260de8b01802db0466a9aadc5e070cdab52d60b41132087a2bc1892d8f5294515c595ec5306c68035378b35c912f0dddade9dfd15c93ce31aacfe54c61f8ca69c8441897ac46370b9dbe7e31917c7235b2b81fd805bb907677a52de7a1a10db66bd5b0fa822fb1073c5894288e20a392c5e3d0db38f295917f71b0d98af0786df5392169889ad104ac1bfdb0a87c41268fbb66995d7f6f0adc60f945e70283c2ea49b8eeef38b4051faa9c714b412dd76c2f7ea358d7637f1c295ec920e7630f705ba7f7373fe50b")] // test
    public void CorrectlyGeneratesRing_WithFourKeys(string prefix_hash_hex, string image_hex, int pubs_count, string pub_0_hex, string pub_1_hex, string pub_2_hex, string pub_3_hex, string sec_hex, int sec_index, string expected_signature_hex)
    {
        byte[] prefix_hash = MoneroUtils.HexBytesToBinary(prefix_hash_hex);
        byte[] image = MoneroUtils.HexBytesToBinary(image_hex);
        byte[] pub_0 = MoneroUtils.HexBytesToBinary(pub_0_hex);
        byte[] pub_1 = MoneroUtils.HexBytesToBinary(pub_1_hex);
        byte[] pub_2 = MoneroUtils.HexBytesToBinary(pub_2_hex);
        byte[] pub_3 = MoneroUtils.HexBytesToBinary(pub_3_hex);
        byte[] sec = MoneroUtils.HexBytesToBinary(sec_hex);

        var pubs = new byte[4][];
        pubs[0] = pub_0;
        pubs[1] = pub_1;
        pubs[2] = pub_2;
        pubs[3] = pub_3;
        byte[] sig = RingSig.generate_ring_signature(prefix_hash, image, pubs, pubs_count, sec, sec_index);

        bool check_result = RingSig.check_ring_signature(prefix_hash, image, pubs, pubs_count, sig);

        Assert.True(check_result);
    }

}
