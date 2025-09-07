using System.Buffers.Binary;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;
using System.Runtime.CompilerServices;
using Aes = System.Runtime.Intrinsics.Arm.Aes;

namespace RoccaSDotNet;

internal sealed class RoccaSArm : IDisposable
{
    private readonly Vector128<byte>[] _s = GC.AllocateArray<Vector128<byte>>(7, pinned: true);
    private bool _disposed;

    internal static bool IsSupported() => Aes.IsSupported;

    internal RoccaSArm(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
    {
        Vector128<byte> n = Vector128.Create(nonce);
        Vector128<byte> k0 = Vector128.Create(key[..16]);
        Vector128<byte> k1 = Vector128.Create(key[16..]);
        Vector128<byte> z0 = Vector128.Create((ReadOnlySpan<byte>)[205, 101, 239, 35, 145, 68, 55, 113, 34, 174, 40, 215, 152, 47, 138, 66]);
        Vector128<byte> z1 = Vector128.Create((ReadOnlySpan<byte>)[188, 219, 137, 129, 165, 219, 181, 233, 47, 59, 77, 236, 207, 251, 192, 181]);

        _s[0] = k1;
        _s[1] = n;
        _s[2] = z0;
        _s[3] = k0;
        _s[4] = z1;
        _s[5] = n ^ k1;
        _s[6] = Vector128<byte>.Zero;

        for (int i = 0; i < 16; i++) {
            Round(z0, z1);
        }

        _s[0] ^= k0;
        _s[1] ^= k0;
        _s[2] ^= k1;
        _s[3] ^= k0;
        _s[4] ^= k0;
        _s[5] ^= k1;
        _s[6] ^= k1;
    }

    internal void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData = default)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(RoccaSArm)); }
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
            pad.Clear();
            plaintext[i..].CopyTo(pad);
            Encryption(pad, pad);
            pad[..(plaintext.Length % 32)].CopyTo(ciphertext[i..^RoccaS.TagSize]);
        }
        CryptographicOperations.ZeroMemory(pad);

        Finalization(ciphertext[^RoccaS.TagSize..], (ulong)associatedData.Length, (ulong)plaintext.Length);
    }

    internal void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> associatedData = default)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(RoccaSArm)); }
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

        Span<byte> computedTag = stackalloc byte[RoccaS.TagSize];
        Finalization(computedTag, (ulong)associatedData.Length, (ulong)plaintext.Length);

        if (!CryptographicOperations.FixedTimeEquals(computedTag, ciphertext[^RoccaS.TagSize..])) {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(computedTag);
            throw new CryptographicException();
        }
    }

    private void Round(Vector128<byte> x0, Vector128<byte> x1)
    {
        Vector128<byte> sNew0 = _s[6] ^ _s[1];
        Vector128<byte> sNew1 = Aes.MixColumns(Aes.Encrypt(_s[0], Vector128<byte>.Zero)) ^ x0;
        Vector128<byte> sNew2 = Aes.MixColumns(Aes.Encrypt(_s[1], Vector128<byte>.Zero)) ^ _s[0];
        Vector128<byte> sNew3 = Aes.MixColumns(Aes.Encrypt(_s[2], Vector128<byte>.Zero)) ^ _s[6];
        Vector128<byte> sNew4 = Aes.MixColumns(Aes.Encrypt(_s[3], Vector128<byte>.Zero)) ^ x1;
        Vector128<byte> sNew5 = Aes.MixColumns(Aes.Encrypt(_s[4], Vector128<byte>.Zero)) ^ _s[3];
        Vector128<byte> sNew6 = Aes.MixColumns(Aes.Encrypt(_s[5], Vector128<byte>.Zero)) ^ _s[4];

        _s[0] = sNew0;
        _s[1] = sNew1;
        _s[2] = sNew2;
        _s[3] = sNew3;
        _s[4] = sNew4;
        _s[5] = sNew5;
        _s[6] = sNew6;
    }

    private void ProcessAd(ReadOnlySpan<byte> associatedData)
    {
        Vector128<byte> ad0 = Vector128.Create(associatedData[..16]);
        Vector128<byte> ad1 = Vector128.Create(associatedData[16..]);
        Round(ad0, ad1);
    }

    private void Encryption(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext)
    {
        Vector128<byte> m0 = Vector128.Create(plaintext[..16]);
        Vector128<byte> m1 = Vector128.Create(plaintext[16..]);

        Vector128<byte> c0 = Aes.MixColumns(Aes.Encrypt(_s[3] ^ _s[5], Vector128<byte>.Zero)) ^ _s[0] ^ m0;
        Vector128<byte> c1 = Aes.MixColumns(Aes.Encrypt(_s[4] ^ _s[6], Vector128<byte>.Zero)) ^ _s[2] ^ m1;
        Round(m0, m1);

        c0.CopyTo(ciphertext[..16]);
        c1.CopyTo(ciphertext[16..]);
    }

    private void Decryption(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext)
    {
        Vector128<byte> c0 = Vector128.Create(ciphertext[..16]);
        Vector128<byte> c1 = Vector128.Create(ciphertext[16..]);

        Vector128<byte> m0 = Aes.MixColumns(Aes.Encrypt(_s[3] ^ _s[5], Vector128<byte>.Zero)) ^ _s[0] ^ c0;
        Vector128<byte> m1 = Aes.MixColumns(Aes.Encrypt(_s[4] ^ _s[6], Vector128<byte>.Zero)) ^ _s[2] ^ c1;
        Round(m0, m1);

        m0.CopyTo(plaintext[..16]);
        m1.CopyTo(plaintext[16..]);
    }

    private void DecryptionPartial(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext)
    {
        Span<byte> pad = stackalloc byte[32], pad0 = pad[..16], pad1 = pad[16..];
        pad.Clear();
        ciphertext.CopyTo(pad);
        Vector128<byte> c0 = Vector128.Create((ReadOnlySpan<byte>)pad0);
        Vector128<byte> c1 = Vector128.Create((ReadOnlySpan<byte>)pad1);

        Vector128<byte> m0 = Aes.MixColumns(Aes.Encrypt(_s[3] ^ _s[5], Vector128<byte>.Zero)) ^ _s[0] ^ c0;
        Vector128<byte> m1 = Aes.MixColumns(Aes.Encrypt(_s[4] ^ _s[6], Vector128<byte>.Zero)) ^ _s[2] ^ c1;

        m0.CopyTo(pad0);
        m1.CopyTo(pad1);
        pad[..ciphertext.Length].CopyTo(plaintext);

        pad[ciphertext.Length..].Clear();
        Vector128<byte> p0 = Vector128.Create((ReadOnlySpan<byte>)pad0);
        Vector128<byte> p1 = Vector128.Create((ReadOnlySpan<byte>)pad1);
        Round(p0, p1);
    }

    private void Finalization(Span<byte> tag, ulong associatedDataLength, ulong plaintextLength)
    {
        Span<byte> lengths = stackalloc byte[32], ad = lengths[..16], p = lengths[16..];
        BinaryPrimitives.WriteUInt128LittleEndian(ad, associatedDataLength * 8);
        BinaryPrimitives.WriteUInt128LittleEndian(p, plaintextLength * 8);
        Vector128<byte> l0 = Vector128.Create((ReadOnlySpan<byte>)ad);
        Vector128<byte> l1 = Vector128.Create((ReadOnlySpan<byte>)p);

        for (int i = 0; i < 16; i++) {
            Round(l0, l1);
        }

        Vector128<byte> t0 = _s[0] ^ _s[1] ^ _s[2] ^ _s[3];
        Vector128<byte> t1 = _s[4] ^ _s[5] ^ _s[6];
        t0.CopyTo(tag[..16]);
        t1.CopyTo(tag[16..]);
    }

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public void Dispose()
    {
        if (_disposed) { return; }
        for (int i = 0; i < _s.Length; i++) {
            _s[i] = Vector128<byte>.Zero;
        }
        _disposed = true;
    }
}
