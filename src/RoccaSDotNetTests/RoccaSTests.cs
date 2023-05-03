using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;
using RoccaSDotNet;

namespace RoccaSDotNetTests;

[TestClass]
public class RoccaSTests
{
    // https://github.com/jedisct1/zig-rocca-s/blob/master/src/main.zig
    // https://www.ietf.org/archive/id/draft-nakano-rocca-s-03.html#name-test-vector
    public static IEnumerable<object[]> TestVectors()
    {
        // Empty test
        yield return new object[]
        {
            "d70bfa63d7658fb527b6c6ceb43f11b1696044eb4dbd9d3db83de552b61551b0",
            "",
            "00000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            ""
        };
        // Test Vector 1
        yield return new object[]
        {
            "9ac3326495a8d414fe407f47b54410502481cf79cab8c0a669323e07711e46170de5b2fbba0fae8de7c1fccaeefc362624fcfdc15f8bb3e64457e8b7e37557bb8df934d1483710c9410f6a089c4ced9791901b7e2e661206202db2cc7a24a386",
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000"
        };
        // Test Vector 2
        yield return new object[]
        {
            "559ecb253bcfe26b483bf00e9c748345978ff921036a6c1fdcb712172836504fbc64d430a73fc67acd3c3b9c1976d80790f48357e7fe0c0682624569d3a658fbc1fdf39762eca77da8b0f1dae5fff75a92fb0adfa7940a28c8cadbbbe8e4ca8d",
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "01010101010101010101010101010101",
            "0101010101010101010101010101010101010101010101010101010101010101",
            "0101010101010101010101010101010101010101010101010101010101010101"
        };
        // Test Vector 3
        yield return new object[]
        {
            "b5fc4e2a72b86d1a133c0f0202bdf790af14a24b2cdb676e427865e12fcc9d3021d18418fc75dc1912dd2cd79a3beeb2a98b235de2299b9dda93fd2b5ac8f436a078e1351ef2420c8e3a93fd31f5b1135b15315a5f205534148efbcd63f79f00",
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        };
    }
    
    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { RoccaS.TagSize, 1, RoccaS.NonceSize, RoccaS.KeySize, RoccaS.TagSize };
        yield return new object[] { RoccaS.TagSize, 0, RoccaS.NonceSize + 1, RoccaS.KeySize, RoccaS.TagSize };
        yield return new object[] { RoccaS.TagSize, 0, RoccaS.NonceSize - 1, RoccaS.KeySize, RoccaS.TagSize };
        yield return new object[] { RoccaS.TagSize, 0, RoccaS.NonceSize, RoccaS.KeySize + 1, RoccaS.TagSize };
        yield return new object[] { RoccaS.TagSize, 0, RoccaS.NonceSize, RoccaS.KeySize - 1, RoccaS.TagSize };
    }
    
    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Encrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> c = stackalloc byte[ciphertext.Length / 2];
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);
        
        RoccaS.Encrypt(c, p, n, k, ad);
        
        Assert.AreEqual(ciphertext, Convert.ToHexString(c).ToLower());
    }
    
    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Encrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];
        
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => RoccaS.Encrypt(c, p, n, k, ad));
    }
    
    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> p = stackalloc byte[plaintext.Length / 2];
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);
        
        RoccaS.Decrypt(p, c, n, k, ad);
        
        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }
    
    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Tampered(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        var p = new byte[plaintext.Length / 2];
        var parameters = new List<byte[]>
        {
            Convert.FromHexString(ciphertext),
            Convert.FromHexString(nonce),
            Convert.FromHexString(key),
            Convert.FromHexString(associatedData)
        };
        
        foreach (var param in parameters.Where(param => param.Length > 0)) {
            param[0]++;
            Assert.ThrowsException<CryptographicException>(() => RoccaS.Decrypt(p, parameters[0], parameters[1], parameters[2], parameters[3]));
            param[0]--;
        }
        Assert.IsTrue(p.SequenceEqual(new byte[p.Length]));
    }
    
    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Decrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize)
    {
        var p = new byte[plaintextSize];
        var c = new byte[ciphertextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];
        
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => RoccaS.Decrypt(p, c, n, k, ad));
    }
}