namespace RoccaSDotNet;

public static class RoccaS
{
    public const int KeySize = 32;
    public const int NonceSize = 16;
    public const int TagSize = 32;

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        if (ciphertext.Length != plaintext.Length + TagSize) { throw new ArgumentOutOfRangeException(nameof(ciphertext), ciphertext.Length, $"{nameof(ciphertext)} must be {plaintext.Length + TagSize} bytes long."); }
        if (nonce.Length != NonceSize) { throw new ArgumentOutOfRangeException(nameof(nonce), nonce.Length, $"{nameof(nonce)} must be {NonceSize} bytes long."); }
        if (key.Length != KeySize) { throw new ArgumentOutOfRangeException(nameof(key), key.Length, $"{nameof(key)} must be {KeySize} bytes long."); }

        if (RoccaSx86.IsSupported()) {
            using var rocca = new RoccaSx86(key, nonce);
            rocca.Encrypt(ciphertext, plaintext, associatedData);
        }
        else if (RoccaSArm.IsSupported()) {
            using var rocca = new RoccaSArm(key, nonce);
            rocca.Encrypt(ciphertext, plaintext, associatedData);
        }
        else {
            throw new PlatformNotSupportedException();
        }
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        if (ciphertext.Length < TagSize) { throw new ArgumentOutOfRangeException(nameof(ciphertext), ciphertext.Length, $"{nameof(ciphertext)} must be at least {TagSize} bytes long."); }
        if (plaintext.Length != ciphertext.Length - TagSize) { throw new ArgumentOutOfRangeException(nameof(plaintext), plaintext.Length, $"{nameof(plaintext)} must be {ciphertext.Length - TagSize} bytes long."); }
        if (nonce.Length != NonceSize) { throw new ArgumentOutOfRangeException(nameof(nonce), nonce.Length, $"{nameof(nonce)} must be {NonceSize} bytes long."); }
        if (key.Length != KeySize) { throw new ArgumentOutOfRangeException(nameof(key), key.Length, $"{nameof(key)} must be {KeySize} bytes long."); }

        if (RoccaSx86.IsSupported()) {
            using var rocca = new RoccaSx86(key, nonce);
            rocca.Decrypt(plaintext, ciphertext, associatedData);
        }
        else if (RoccaSArm.IsSupported()) {
            using var rocca = new RoccaSArm(key, nonce);
            rocca.Decrypt(plaintext, ciphertext, associatedData);
        }
        else {
            throw new PlatformNotSupportedException();
        }
    }
}
