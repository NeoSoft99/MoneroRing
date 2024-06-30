using MoneroRing.Crypto;

namespace MoneroRing.UnitTest;

public class UnitTest_generate_key_derivation
{
    [Theory]
        [InlineData(
            "fdfd97d2ea9f1c25df773ff2c973d885653a3ee643157eb0ae2b6dd98f0b6984",
            "eb2bd1cf0c5e074f9dbf38ebbc99c316f54e21803048c687a3bb359f7a713b02",
            "4e0bd2c41325a1b89a9f7413d4d05e0a5a4936f241dccc3c7d0c539ffe00ef67")]
        [InlineData(
            "1ebf8c3c296bb91708b09d9a8e0639ccfd72556976419c7dc7e6dfd7599218b9",
            "e49f363fd5c8fc1f8645983647ca33d7ec9db2d255d94cd538a3cc83153c5f04",
            "72903ec8f9919dfcec6efb5535490527b573b3d77f9890386d373c02bf368934")]
        [InlineData(
            "3e3047a633b1f84250ae11b5c8e8825a3df4729f6cbe4713b887db62f268187d",
            "6df324e24178d91c640b75ab1c6905f8e6bb275bc2c2a5d9b9ecf446765a5a05",
            "9dcac9c9e87dd96a4115d84d587218d8bf165a0527153b1c306e562fe39a46ab")]
        [InlineData(
            "ba7b73dfa3185875538871e425a4ec8d5f16cac09db14cefd5510568a66eff3e",
            "c9b52fd93365c57220178996d97cc979c752d56a8199568dd2c882486f7f1d0a",
            "f5bb6522dea0c40229928766fb7019ac4be3022469c8d825ae965b8af3d3c517")]
        [InlineData(
            "45f6f692d8dc545deff096b048e94ee25acd7bf67fb49f7d83107f9969b9bc67",
            "4451358855fb52b2199db97b33b6d7d47ac2b4067ecdf5ed20bb32162543270a",
            "bcdc1f0c4b6cc6bc1847728630c3060dd1982d51bb06873f53a4a13998510cc1")]
        [InlineData(
            "71329cf72de45f5b98fdd233707501f87aa4130db40b3570527801d5d24e2be5",
            "b8bc1ee2987bb7451e90c6e7885ce5f6d2f4ae12e5e724ab8432769af66a2307",
            "7498d5bf0b69e08653f6d420a17f866dd2bd490ab43074f46065cb501fe7e2d8")]
        [InlineData(
            "748c56d5104fb888c4143dd3ae13e578100cd87f4af1be562ee8401d2eec81ad",
            "659f545d8661711e337ce3c4e47770c9f55c25b0c087a3a794403febd3f1600d",
            "796b938b108654542a27155a760853101aa896eba019c659e0bf357db225603f")]
        [InlineData(
            "1a2c6c3f4c305b93e6c09604f108d46c988e16bb78a58bbc95da5e148e9ca856",
            "668b766d1a3b09fc41a7f27ca50a1ffce1f6456b9d3613527f0cb86e1eed6705",
            "6e9e6dba0861417979f668755c66e09cba4b06d07eca5bcadf6e8dd2f704eef4")]
        [InlineData(
            "6ac060a711ce299a7ee47a74f7b3ab9d53ed8bb19fe3bf5f786745babf22e3c1",
            "00b5bbef9ad292f0289126a0ece082c9c535324c5ee0fd1534f7801777337f05",
            "f59b6f915e270452eccdf7172f1cf0fe702beca9067673ea3ef7a4920066a1cc")]
        [InlineData(
            "aa1a5a28ec965d1f4838c2781628cafa9867dda2153990c7fc4d19dbf1cae3b2",
            "76c1838f52d761c3738500f240b14e48ada3c1e92081d5f60e53d642fffc610b",
            "e4ced0d7c6d10f0dd4f55a4d7b69ad17b692179b0038013dc8ac287fd4360cf2")]
        [InlineData(
            "1ad93701cb458404ebe32645876bc3c3ca4c318bd5634d9cf2a1412fc8df92af",
            "69ecdac81dd2c712c4383c7a602d0ce40b66f7afa5371b7b1430e6672679a00a",
            "9ba0f9c3ebd17af8a9c5ff29fc5fdf01555d77a61e0056d7f283a8b28ae84218")]
        [InlineData(
            "e2dcbaddd4f369b223d056e0e254614e274079b0d28636aa7c7660fd6a1c3b17",
            "435e792c42e18d17624cd2a6740ba41c983c5ea506146b65762990e4aa089201",
            "230641ed77b79c239f9e9858d8076b30173822fc7469ada85f85d5516aedd3fa")]
        [InlineData(
            "d9a8ca485970b266e0a805acf4a193b07f61f638b6673aec409b2b1f1040856a",
            "6f2ec363ddf334f3b25df564e142945f0c7c10f64dded0ab95251aeebd41c200",
            "4ac220b3572ccd752b0b84100f8ae74a2caba2c89b39bb5d12c2033d91a57b8e")]
        [InlineData(
            "a4ff4c9aa679a6ddc2a4abf73bb550e675dbfe0e5f7e07767e896fd1a6dbaba2",
            "39cc6daeeda5ab5d753781fa47e61c6de8722c6e0dffa30e7c0ad6e2cb9d400b",
            "6d45efb1033b1893d8161f93d63532856b3977521c3406482e81d0adf80ad9d4")]
        [InlineData(
            "8c92d3d3aebfc3098ba8244ee1c2b52904c0696b9a96f45c8cc2535ece49105e",
            "82f9079fb392bafc9a022457cf87fdf83dddfd2a929a0c0b6d48eaf5495d9f0e",
            "c87ab7381e44274bc81bcb3ea2fa6242c4b553a0d0752d6992eed9c578df82d7")]
    public void GenerateKeyDerivation_Test(string pubKeyHex, string secKeyHex, string expectedDerivationHex)
    {
        byte[] pubKey = HexStringToByteArray(pubKeyHex);
        byte[] secKey = HexStringToByteArray(secKeyHex);
        byte[] expectedDerivation = HexStringToByteArray(expectedDerivationHex);
        byte[] actualDerivation = new byte[32];

        bool result = RingSig.generate_key_derivation(pubKey, secKey, actualDerivation);

        Assert.True(result);
        Assert.Equal(expectedDerivation, actualDerivation);
    }
    
    [Theory]
    [InlineData("d875a37d7ffe687d74dcbcfb1d7b48812c49505e322a43568605b2219a8047b2", "869be2bc50c3f12a5c83f0d581e6d5585391daed3c651e81f69868d55e6d280d")]
    [InlineData(
        "e667e7a144d40b9280026dadefe7bda1fa6f897a03650b2ad842ec2c3e30c782",
        "4603512009eadb28bc4ab49ee9693179b81d0fc10af3d11ea7a1b3e8aceb6b0f")]
    [InlineData(
        "570d215a4095e43440c21373afa30ca5c9b420bbc1530ef029bc6225944df7cd",
        "8a2bdda64e82f5e2844dcfa8152a9afcf8a7839d845de8b0bed61d5475d8fd09")]
    [InlineData(
        "ffc0ab99873d7e9e0f650f9c7b4ac9d5c371d584dda752658cc903b6cc0c6271",
        "697bd39b460702f72b0a56adff6ecb92c6e3eafaf3f6421433f688aea9958c0e")]
    [InlineData(
        "7d5c23fd3adc8ae0c2b015c8399f356d8efda2aede07c5b6175592a101da7828",
        "750749e8f32e0ed80082690cb0b277efddd3f8bc1192327aaf54d527df01fa0e")]
    [InlineData(
        "f6b57fa88847f5548dcb4f476a1d3ae6c1c353ff659ff60aa7ed99924e5dc38f",
        "961dd461b5a2f7990c70327a3cd6ba99d179dc9d9691b14624b225282f0dee04")]
    public void GenerateKeyDerivation_NegativeTest(string pubKeyHex, string secKeyHex)
    {
        byte[] pubKey = HexStringToByteArray(pubKeyHex);
        byte[] secKey = HexStringToByteArray(secKeyHex);
        byte[] actualDerivation = new byte[32];
        bool result = RingSig.generate_key_derivation(pubKey, secKey, actualDerivation);

        Assert.False(result);
    }
    
    [Fact]
    public void SharedSecret_Test()
    {
        byte[] sec1 = new byte[32];
        byte[] pub1 = new byte[32];
        RingSig.generate_keys(pub1, sec1);
        byte[] sec2 = new byte[32];
        byte[] pub2 = new byte[32];
        RingSig.generate_keys(pub2, sec2);

        byte[] derivation1 = new byte[32];
        byte[] derivation2 = new byte[32];
        
        bool result1 = RingSig.generate_key_derivation(pub1, sec2, derivation1);
        bool result2 = RingSig.generate_key_derivation(pub2, sec1, derivation2);
        
        Assert.True(result1);
        Assert.True(result2);
        Assert.Equal(derivation1, derivation2);
    }
    
    private static byte[] HexStringToByteArray(string hex)
    {
        int numberChars = hex.Length;
        byte[] bytes = new byte[numberChars / 2];
        for (int i = 0; i < numberChars; i += 2)
        {
            bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
        }
        return bytes;
    }
}
