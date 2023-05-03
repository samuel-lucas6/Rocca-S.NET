using System.Buffers.Binary;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;
using Aes = System.Runtime.Intrinsics.X86.Aes;

namespace RoccaSDotNet;

internal static class RoccaSx86
{
    private static Vector128<byte> s0, s1, s2, s3, s4, s5, s6;
    
    internal static bool IsSupported() => Aes.IsSupported;
    
    internal static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Initialization(nonce, key);
        
        int i = 0;
        Span<byte> pad = stackalloc byte[32];
        while (i + 32 <= associatedData.Length) {
            ProcessAd(associatedData.Slice(i, 32));
            i += 32;
        }
        if (associatedData.Length % 32 != 0) {
            pad.Clear();
            associatedData[i..].CopyTo(pad);
            ProcessAd(pad);
        }
        
        i = 0;
        while (i + 32 <= plaintext.Length) {
            Encryption(ciphertext.Slice(i, 32), plaintext.Slice(i, 32));
            i += 32;
        }
        if (plaintext.Length % 32 != 0) {
            Span<byte> tmp = stackalloc byte[32];
            pad.Clear();
            plaintext[i..].CopyTo(pad);
            Encryption(tmp, pad);
            tmp[..(plaintext.Length % 32)].CopyTo(ciphertext[i..^RoccaS.TagSize]);
        }
        CryptographicOperations.ZeroMemory(pad);
        
        Finalization(ciphertext[^RoccaS.TagSize..], (ulong)associatedData.Length, (ulong)plaintext.Length);
    }
    
    internal static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Initialization(nonce, key);
        
        int i = 0;
        while (i + 32 <= associatedData.Length) {
            ProcessAd(associatedData.Slice(i, 32));
            i += 32;
        }
        if (associatedData.Length % 32 != 0) {
            Span<byte> pad = stackalloc byte[32];
            pad.Clear();
            associatedData[i..].CopyTo(pad);
            ProcessAd(pad);
            CryptographicOperations.ZeroMemory(pad);
        }
        
        i = 0;
        while (i + 32 <= plaintext.Length) {
            Decryption(plaintext.Slice(i, 32), ciphertext.Slice(i, 32));
            i += 32;
        }
        if (plaintext.Length % 32 != 0) {
            DecryptionPartial(plaintext[i..], ciphertext[i..^RoccaS.TagSize]);
        }
        
        Span<byte> tag = stackalloc byte[RoccaS.TagSize];
        Finalization(tag, (ulong)associatedData.Length, (ulong)plaintext.Length);
        
        if (!CryptographicOperations.FixedTimeEquals(tag, ciphertext[^RoccaS.TagSize..])) {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(tag);
            throw new CryptographicException();
        }
    }
    
    private static void Initialization(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key)
    {
        Vector128<byte> n = Vector128.Create(nonce);
        Vector128<byte> k0 = Vector128.Create(key[..16]);
        Vector128<byte> k1 = Vector128.Create(key[16..]);
        Vector128<byte> z0 = Vector128.Create((ReadOnlySpan<byte>)stackalloc byte[] { 205, 101, 239, 35, 145, 68, 55, 113, 34, 174, 40, 215, 152, 47, 138, 66 });
        Vector128<byte> z1 = Vector128.Create((ReadOnlySpan<byte>)stackalloc byte[] { 188, 219, 137, 129, 165, 219, 181, 233, 47, 59, 77, 236, 207, 251, 192, 181 });
        ReadOnlySpan<byte> zero = new byte[16];
        
        s0 = k1;
        s1 = n;
        s2 = z0;
        s3 = k0;
        s4 = z1;
        s5 = n ^ k1;
        s6 = Vector128.Create(zero);
        
        for (int i = 0; i < 16; i++) {
            Round(z0, z1);
        }
        
        s0 ^= k0;
        s1 ^= k0;
        s2 ^= k1;
        s3 ^= k0;
        s4 ^= k0;
        s5 ^= k1;
        s6 ^= k1;
    }
    
    private static void Round(Vector128<byte> x0, Vector128<byte> x1)
    {
        Vector128<byte> sNew0 = s6 ^ s1;
        Vector128<byte> sNew1 = Aes.Encrypt(s0, x0);
        Vector128<byte> sNew2 = Aes.Encrypt(s1, s0);
        Vector128<byte> sNew3 = Aes.Encrypt(s2, s6);
        Vector128<byte> sNew4 = Aes.Encrypt(s3, x1);
        Vector128<byte> sNew5 = Aes.Encrypt(s4, s3);
        Vector128<byte> sNew6 = Aes.Encrypt(s5, s4);
        
        s0 = sNew0;
        s1 = sNew1;
        s2 = sNew2;
        s3 = sNew3;
        s4 = sNew4;
        s5 = sNew5;
        s6 = sNew6;
    }
    
    private static void ProcessAd(ReadOnlySpan<byte> associatedData)
    {
        Vector128<byte> ad0 = Vector128.Create(associatedData[..16]);
        Vector128<byte> ad1 = Vector128.Create(associatedData[16..]);
        Round(ad0, ad1);
    }
    
    private static void Encryption(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext)
    {
        Vector128<byte> m0 = Vector128.Create(plaintext[..16]);
        Vector128<byte> m1 = Vector128.Create(plaintext[16..]);
        
        Vector128<byte> c0 = Aes.Encrypt(s3 ^ s5, s0) ^ m0;
        Vector128<byte> c1 = Aes.Encrypt(s4 ^ s6, s2) ^ m1;
        Round(m0, m1);
        
        c0.CopyTo(ciphertext[..16]);
        c1.CopyTo(ciphertext[16..]);
    }
    
    private static void Decryption(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext)
    {
        Vector128<byte> c0 = Vector128.Create(ciphertext[..16]);
        Vector128<byte> c1 = Vector128.Create(ciphertext[16..]);
        
        Vector128<byte> m0 = Aes.Encrypt(s3 ^ s5, s0) ^ c0;
        Vector128<byte> m1 = Aes.Encrypt(s4 ^ s6, s2) ^ c1;
        Round(m0, m1);
        
        m0.CopyTo(plaintext[..16]);
        m1.CopyTo(plaintext[16..]);
    }
    
    private static void DecryptionPartial(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext)
    {
        var pad = new byte[32];
        ciphertext.CopyTo(pad);
        Vector128<byte> c0 = Vector128.Create(pad[..16]);
        Vector128<byte> c1 = Vector128.Create(pad[16..]);
        
        Vector128<byte> m0 = Aes.Encrypt(s3 ^ s5, s0) ^ c0;
        Vector128<byte> m1 = Aes.Encrypt(s4 ^ s6, s2) ^ c1;
        
        Span<byte> p = pad;
        m0.CopyTo(p[..16]);
        m1.CopyTo(p[16..]);
        p[..ciphertext.Length].CopyTo(plaintext);
        
        p[ciphertext.Length..].Clear();
        Vector128<byte> p0 = Vector128.Create(pad[..16]);
        Vector128<byte> p1 = Vector128.Create(pad[16..]);
        Round(p0, p1);
    }
    
    private static void Finalization(Span<byte> tag, ulong associatedDataLength, ulong plaintextLength)
    {
        byte[] ad = new byte[16], p = new byte[16];
        BinaryPrimitives.WriteUInt128LittleEndian(ad, associatedDataLength * 8);
        BinaryPrimitives.WriteUInt128LittleEndian(p, plaintextLength * 8);
        Vector128<byte> l0 = Vector128.Create(ad);
        Vector128<byte> l1 = Vector128.Create(p);
        
        for (int i = 0; i < 16; i++) {
            Round(l0, l1);
        }
        
        Vector128<byte> t0 = s0 ^ s1 ^ s2 ^ s3;
        Vector128<byte> t1 = s4 ^ s5 ^ s6;
        t0.CopyTo(tag[..16]);
        t1.CopyTo(tag[16..]);
    }
}