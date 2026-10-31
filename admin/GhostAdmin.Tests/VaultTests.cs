using System.Text;
using GhostAdmin.Core;
using Xunit;

namespace GhostAdmin.Tests;

public class VaultTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "gv-" + Guid.NewGuid().ToString("N"));
    private string P => Path.Combine(_dir, "vault.bin");
    public VaultTests() { Directory.CreateDirectory(_dir); }
    public void Dispose() { try { Directory.Delete(_dir, true); } catch (IOException) { } }
    private const string Pw = "correct horse battery";
    private const int Fast = 100_000;   // minimum the format accepts; keeps tests quick

    [Fact] public void RoundTripKeepsEverything()
    {
        using (var v = Vault.Create(P, Pw, Fast)) { v.Data.Snapshot = "{\"accounts\":[]}"; v.Data.RelayPort = 9001; v.Save(); }
        using var w = Vault.Open(P, Pw);
        Assert.Equal("{\"accounts\":[]}", w.Data.Snapshot); Assert.Equal(9001, w.Data.RelayPort);
        Assert.True(w.Data.AdminToken.Length >= 32);
    }

    [Fact] public void WrongPasswordIsRejected()
    {
        Vault.Create(P, Pw, Fast).Dispose();
        var ex = Assert.Throws<VaultException>(() => Vault.Open(P, Pw + "x"));
        Assert.Contains("Wrong password", ex.Message);
    }

    [Fact] public void ShortPasswordAndOverwriteAreRefused()
    {
        Assert.Throws<ArgumentException>(() => Vault.Create(P, "short", Fast));
        Vault.Create(P, Pw, Fast).Dispose();
        Assert.Throws<VaultException>(() => Vault.Create(P, "another long password", Fast));
    }

    [Fact] public void NothingReadableIsOnDisk()
    {
        string token;
        using (var v = Vault.Create(P, Pw, Fast)) { token = v.Data.AdminToken; v.Data.Snapshot = "{\"accounts\":[{\"username\":\"alice_test\"}]}"; v.Save(); }
        var raw = File.ReadAllBytes(P); var text = Encoding.Latin1.GetString(raw);
        Assert.DoesNotContain(token, text); Assert.DoesNotContain("alice_test", text); Assert.DoesNotContain("accounts", text); Assert.DoesNotContain("AdminToken", text);
    }

    [Fact] public void ChangingAnySingleByteMakesTheVaultUnopenable()
    {
        Vault.Create(P, Pw, Fast).Dispose();
        var good = File.ReadAllBytes(P);
        for (int i = 0; i < good.Length; i++)
        {
            var bad = (byte[])good.Clone(); bad[i] ^= 0x01; File.WriteAllBytes(P, bad);
            Assert.Throws<VaultException>(() => Vault.Open(P, Pw));
        }
    }

    [Fact] public void EverySaveUsesAFreshNonce()
    {
        using var v = Vault.Create(P, Pw, Fast);
        var seen = new HashSet<string>();
        for (int i = 0; i < 20; i++) { v.Save(); seen.Add(Convert.ToHexString(File.ReadAllBytes(P).AsSpan(24, 12))); }
        Assert.Equal(20, seen.Count);
    }

    [Fact] public void CheckPasswordAcceptsOnlyTheRightOne()
    {
        using var v = Vault.Create(P, Pw, Fast);
        Assert.True(v.CheckPassword(Pw)); Assert.False(v.CheckPassword("nope nope nope")); Assert.False(v.CheckPassword(""));
    }

    [Fact] public void GarbageFilesAreNotAccepted()
    {
        File.WriteAllBytes(P, new byte[10]); Assert.Throws<VaultException>(() => Vault.Open(P, Pw));
        File.WriteAllBytes(P, Encoding.ASCII.GetBytes("GAV1" + new string('x', 100))); Assert.Throws<VaultException>(() => Vault.Open(P, Pw));
    }
}

public class GateTests
{
    private const string Pw = "correct horse battery";
    [Fact] public void WrongPasswordsSlowDownAndRightOneResets()
    {
        var path = Path.Combine(Path.GetTempPath(), "gg-" + Guid.NewGuid().ToString("N") + ".bin");
        try
        {
            using var v = Vault.Create(path, Pw, 100_000);
            var now = new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var g = new PasswordGate(v, () => now);
            Assert.False(g.TryVerify("bad")); Assert.Equal(TimeSpan.FromSeconds(1), g.Remaining);
            Assert.False(g.TryVerify(Pw), "even the right password is refused while waiting");
            now = now.AddSeconds(1.1); Assert.False(g.TryVerify("bad")); Assert.Equal(TimeSpan.FromSeconds(2), g.Remaining);
            now = now.AddSeconds(2.1); Assert.False(g.TryVerify("bad")); Assert.Equal(TimeSpan.FromSeconds(4), g.Remaining);
            now = now.AddSeconds(4.1); Assert.True(g.TryVerify(Pw)); Assert.Equal(0, g.Failures); Assert.Equal(TimeSpan.Zero, g.Remaining);
            for (int i = 0; i < 12; i++) { now = now.AddMinutes(2); g.TryVerify("bad"); }
            Assert.True(g.Remaining <= TimeSpan.FromSeconds(60));
        }
        finally { File.Delete(path); }
    }
}

public class ParserTests
{
    [Fact] public void FindsTheTunnelAddress()
    {
        Assert.Equal("https://nest-feed-faculty-proceeds.trycloudflare.com",
            TunnelUrlParser.TryParse("2026-10-30T06:29:40Z INF |  https://nest-feed-faculty-proceeds.trycloudflare.com                                      |"));
        Assert.Equal("https://abc-def.trycloudflare.com", TunnelUrlParser.TryParse("HTTPS://ABC-DEF.TRYCLOUDFLARE.COM"));
    }
    [Fact] public void IgnoresCloudflaresOwnApiAndUnrelatedLines()
    {
        Assert.Null(TunnelUrlParser.TryParse("failed to request quick Tunnel: Post \"https://api.trycloudflare.com/tunnel\": context deadline exceeded"));
        Assert.Null(TunnelUrlParser.TryParse("INF Requesting new quick Tunnel on trycloudflare.com..."));
        Assert.Null(TunnelUrlParser.TryParse("https://example.com"));
        Assert.Null(TunnelUrlParser.TryParse(""));
    }
    [Fact] public void InviteMessageHasAddressAndCode()
    {
        var m = InviteMessage.Build("https://x.trycloudflare.com", "CODE123");
        Assert.Contains("https://x.trycloudflare.com", m); Assert.Contains("CODE123", m);
    }
}

public class RetryTests
{
    [Fact] public async Task KeepsTryingUntilItWorksAndAlternatesConnectionType()
    {
        var kinds = new List<bool>(); var seen = new List<int>();
        var n = await TunnelRetry.RunAsync(h => { kinds.Add(h); return Task.FromResult(kinds.Count == 4); }, 8, TimeSpan.Zero, (i, m) => seen.Add(i));
        Assert.Equal(4, n); Assert.Equal(new[] { false, true, false, true }, kinds); Assert.Equal(new[] { 1, 2, 3, 4 }, seen);
    }
    [Fact] public async Task GivesUpAfterTheLimit()
    {
        int calls = 0;
        var n = await TunnelRetry.RunAsync(_ => { calls++; return Task.FromResult(false); }, 5, TimeSpan.Zero);
        Assert.Equal(0, n); Assert.Equal(5, calls);
    }
    [Fact] public async Task StopsAtOnceWhenCancelled()
    {
        using var cts = new CancellationTokenSource(); int calls = 0;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => TunnelRetry.RunAsync(_ => { calls++; cts.Cancel(); return Task.FromResult(false); }, 8, TimeSpan.FromSeconds(30), null, cts.Token));
        Assert.Equal(1, calls);
    }
}
