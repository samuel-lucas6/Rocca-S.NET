using System.Security.Cryptography;

namespace RoccaSDotNet.Tests;

[TestClass]
public class RoccaSTests
{
    // https://github.com/jedisct1/zig-rocca-s/blob/master/src/main.zig
    // https://datatracker.ietf.org/doc/html/draft-nakano-rocca-s-05#appendix-A.2
    public static IEnumerable<object[]> TestVectors()
    {
        // zig-rocca-s - Empty test
        yield return
        [
            "d70bfa63d7658fb527b6c6ceb43f11b1696044eb4dbd9d3db83de552b61551b0",
            "",
            "00000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            ""
        ];
        // zig-rocca-s - Test Vector 4
        yield return
        [
            "e28d9f86288f77115d4ef620e7cedecee4d7de0fce38a9061f813c9805bc1ea7fdf6709eabcfcf75801649edc063579ea08cc645f5197c7ded9c99115775369fe16bae2feff540be2b4ce999d440bc730b7e332e25b6ce4e1a9785b95f6eb1cd",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            "44444444444444444444444444444444",
            "1111111111111111111111111111111122222222222222222222222222222222",
            "808182838485868788898a8b8c8d8e8f9091"
        ];
        // Internet-Draft - Test Vector 1
        yield return
        [
            "9ac3326495a8d414fe407f47b54410502481cf79cab8c0a669323e07711e46170de5b2fbba0fae8de7c1fccaeefc362624fcfdc15f8bb3e64457e8b7e37557bb8df934d1483710c9410f6a089c4ced9791901b7e2e661206202db2cc7a24a386",
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000"
        ];
        // Internet-Draft - Test Vector 2
        yield return
        [
            "559ecb253bcfe26b483bf00e9c748345978ff921036a6c1fdcb712172836504fbc64d430a73fc67acd3c3b9c1976d80790f48357e7fe0c0682624569d3a658fbc1fdf39762eca77da8b0f1dae5fff75a92fb0adfa7940a28c8cadbbbe8e4ca8d",
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "01010101010101010101010101010101",
            "0101010101010101010101010101010101010101010101010101010101010101",
            "0101010101010101010101010101010101010101010101010101010101010101"
        ];
        // Internet-Draft - Test Vector 3
        yield return
        [
            "b5fc4e2a72b86d1a133c0f0202bdf790af14a24b2cdb676e427865e12fcc9d3021d18418fc75dc1912dd2cd79a3beeb2a98b235de2299b9dda93fd2b5ac8f436a078e1351ef2420c8e3a93fd31f5b1135b15315a5f205534148efbcd63f79f00",
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ];
        // Internet-Draft - Test Vector 4
        yield return
        [
            "e8c7adcc58302893b253c544f5d8e62d8fbd81160c2f4a95123962088d29f106422d3f26882fd7b1f650eba86fb19dc14a3bbe8bbfad9ec5b5dd77a4c3f83d2c19ac0393dd47928f",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7",
            "44444444444444444444444444444444",
            "1111111111111111111111111111111122222222222222222222222222222222",
            ""
        ];
        // Internet-Draft - Test Vector 5
        yield return
        [
            "e8c7adcc58302893b253c544f5d8e62d8fbd81160c2f4a95123962088d29f106422d3f26882fd7b1fdee5680476e7e6e49bb0ec78cab2c5f40a535925fa2d82752aba9606426537fc774f06fc0f6fc12",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
            "44444444444444444444444444444444",
            "1111111111111111111111111111111122222222222222222222222222222222",
            ""
        ];
        // Internet-Draft - Test Vector 6
        yield return
        [
            "e8c7adcc58302893b253c544f5d8e62d8fbd81160c2f4a95123962088d29f106422d3f26882fd7b1fdee5680476e7e6e1fc473cdb2dded85c6c674604803963a4b51685fda1f2aa043934736db2fbab6d188a09f5e0d1c0bf3",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8",
            "44444444444444444444444444444444",
            "1111111111111111111111111111111122222222222222222222222222222222",
            ""
        ];
        // Internet-Draft - Test Vector 7
        yield return
        [
            "e8c7adcc58302893b253c544f5d8e62d8fbd81160c2f4a95123962088d29f106422d3f26882fd7b1fdee5680476e7e6e1fc473cdb2dded85c692344f3ab85af0850599a6624a3e936a77768c7717b926cc519081730df447127654d6980bcb02",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
            "44444444444444444444444444444444",
            "1111111111111111111111111111111122222222222222222222222222222222",
            ""
        ];
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return [RoccaS.TagSize - 1, 0, RoccaS.NonceSize, RoccaS.KeySize, RoccaS.TagSize];
        yield return [RoccaS.TagSize, 1, RoccaS.NonceSize, RoccaS.KeySize, RoccaS.TagSize];
        yield return [RoccaS.TagSize, 0, RoccaS.NonceSize + 1, RoccaS.KeySize, RoccaS.TagSize];
        yield return [RoccaS.TagSize, 0, RoccaS.NonceSize - 1, RoccaS.KeySize, RoccaS.TagSize];
        yield return [RoccaS.TagSize, 0, RoccaS.NonceSize, RoccaS.KeySize + 1, RoccaS.TagSize];
        yield return [RoccaS.TagSize, 0, RoccaS.NonceSize, RoccaS.KeySize - 1, RoccaS.TagSize];
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, RoccaS.KeySize);
        Assert.AreEqual(16, RoccaS.NonceSize);
        Assert.AreEqual(32, RoccaS.TagSize);
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

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => RoccaS.Encrypt(c, p, n, k, ad));
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
        var parameters = new Dictionary<string, byte[]>
        {
            { "c", Convert.FromHexString(ciphertext) },
            { "n", Convert.FromHexString(nonce) },
            { "k", Convert.FromHexString(key) },
            { "ad", Convert.FromHexString(associatedData) }
        };

        foreach (var param in parameters.Values.Where(param => param.Length > 0)) {
            param[0]++;
            Assert.ThrowsExactly<CryptographicException>(() => RoccaS.Decrypt(p, parameters["c"], parameters["n"], parameters["k"], parameters["ad"]));
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

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => RoccaS.Decrypt(p, c, n, k, ad));
    }
}
