using System.Security.Cryptography;
using System.Text.Json;

namespace GhostAdmin.Core;

public sealed class VaultException : Exception
{
    public VaultException(string message) : base(message) { }
}

/// <summary>What the admin app keeps on disk, always encrypted. Nothing in here is ever written in plaintext.</summary>
public sealed class VaultData
{
    public string AdminToken { get; set; } = "";
    public string? Snapshot { get; set; }        // the relay's account snapshot (usernames, public keys, invite hashes)
    public int RelayPort { get; set; } = 8443;
    public int AdminPort { get; set; } = 8444;
    public string? CloudflaredPath { get; set; }
}

/// <summary>
/// Encrypted file: "GAV1" | iterations(4, LE) | salt(16) | nonce(12) | tag(16) | ciphertext.
/// Key = PBKDF2-HMAC-SHA256(password, salt, iterations); cipher = AES-256-GCM (.NET platform crypto, nothing home-made).
/// The header is authenticated as associated data, so changing any byte of the file makes opening fail.
/// </summary>
public sealed class Vault : IDisposable
{
    public const int DefaultIterations = 600_000;
    public const int MinPasswordLength = 10;
    private static readonly byte[] Magic = { (byte)'G', (byte)'A', (byte)'V', (byte)'1' };
    private const int SaltLen = 16, NonceLen = 12, TagLen = 16, HeaderLen = 4 + 4 + SaltLen;

    private readonly string _path;
    private readonly byte[] _salt;
    private readonly int _iterations;
    private byte[] _key;
    public VaultData Data { get; private set; }

    private Vault(string path, byte[] salt, int iterations, byte[] key, VaultData data)
    {
        _path = path; _salt = salt; _iterations = iterations; _key = key; Data = data;
    }

    public static bool Exists(string path) => File.Exists(path);

    private static byte[] Derive(string password, byte[] salt, int iterations) =>
        Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, 32);

    public static Vault Create(string path, string password, int iterations = DefaultIterations)
    {
        if (password.Length < MinPasswordLength) throw new ArgumentException($"Use at least {MinPasswordLength} characters.");
        if (File.Exists(path)) throw new VaultException("A vault already exists here; refusing to overwrite it.");
        var salt = RandomNumberGenerator.GetBytes(SaltLen);
        var data = new VaultData { AdminToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(36)).Replace('+', 'a').Replace('/', 'b') };
        var v = new Vault(path, salt, iterations, Derive(password, salt, iterations), data);
        v.Save();
        return v;
    }

    public static Vault Open(string path, string password)
    {
        byte[] file;
        try { file = File.ReadAllBytes(path); } catch (IOException e) { throw new VaultException("Cannot read the vault file: " + e.Message); }
        if (file.Length < HeaderLen + NonceLen + TagLen || !file.AsSpan(0, 4).SequenceEqual(Magic))
            throw new VaultException("This is not a Ghost admin vault.");
        int iterations = BitConverter.ToInt32(file, 4);
        if (iterations < 100_000 || iterations > 10_000_000) throw new VaultException("The vault header is damaged.");
        var salt = file.AsSpan(8, SaltLen).ToArray();
        var nonce = file.AsSpan(HeaderLen, NonceLen).ToArray();
        var tag = file.AsSpan(HeaderLen + NonceLen, TagLen).ToArray();
        var cipher = file.AsSpan(HeaderLen + NonceLen + TagLen).ToArray();
        var key = Derive(password, salt, iterations);
        var plain = new byte[cipher.Length];
        try
        {
            using var gcm = new AesGcm(key, TagLen);
            gcm.Decrypt(nonce, cipher, tag, plain, file.AsSpan(0, HeaderLen));
        }
        catch (CryptographicException)
        {
            CryptographicOperations.ZeroMemory(key);
            throw new VaultException("Wrong password, or the vault file was changed.");
        }
        VaultData? data;
        try { data = JsonSerializer.Deserialize<VaultData>(plain); }
        catch (JsonException) { CryptographicOperations.ZeroMemory(key); throw new VaultException("The vault contents are damaged."); }
        finally { CryptographicOperations.ZeroMemory(plain); }
        if (data == null || data.AdminToken.Length < 32) { CryptographicOperations.ZeroMemory(key); throw new VaultException("The vault contents are damaged."); }
        return new Vault(path, salt, iterations, key, data);
    }

    /// <summary>True if the password is the vault's password (constant-time compare of the derived key).</summary>
    public bool CheckPassword(string password)
    {
        var k = Derive(password, _salt, _iterations);
        try { return CryptographicOperations.FixedTimeEquals(k, _key); }
        finally { CryptographicOperations.ZeroMemory(k); }
    }

    public void Save()
    {
        var plain = JsonSerializer.SerializeToUtf8Bytes(Data);
        var nonce = RandomNumberGenerator.GetBytes(NonceLen);   // fresh for every save
        var header = new byte[HeaderLen];
        Magic.CopyTo(header, 0); BitConverter.GetBytes(_iterations).CopyTo(header, 4); _salt.CopyTo(header, 8);
        var cipher = new byte[plain.Length]; var tag = new byte[TagLen];
        using (var gcm = new AesGcm(_key, TagLen)) gcm.Encrypt(nonce, plain, cipher, tag, header);
        CryptographicOperations.ZeroMemory(plain);
        var all = new byte[HeaderLen + NonceLen + TagLen + cipher.Length];
        header.CopyTo(all, 0); nonce.CopyTo(all, HeaderLen); tag.CopyTo(all, HeaderLen + NonceLen); cipher.CopyTo(all, HeaderLen + NonceLen + TagLen);
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(_path))!);
        var tmp = _path + ".tmp";
        File.WriteAllBytes(tmp, all);
        File.Move(tmp, _path, overwrite: true);
    }

    public void Dispose() { CryptographicOperations.ZeroMemory(_key); _key = new byte[32]; }
}
