using System.Net;
using System.Net.Sockets;
using GhostAdmin.Core;
using Xunit;

namespace GhostAdmin.Tests;

/// <summary>Runs the REAL relay program (built in the same CI job) through the same classes the app uses.</summary>
public class RelayIntegrationTests
{
    private static string? Exe => Environment.GetEnvironmentVariable("GHOST_RELAY_EXE") is { Length: > 0 } p && File.Exists(p) ? p : null;
    private static int FreePort() { var l = new TcpListener(IPAddress.Loopback, 0); l.Start(); var p = ((IPEndPoint)l.LocalEndpoint).Port; l.Stop(); return p; }
    private const string Token = "test-token-test-token-test-token-test-token";

    [SkippableFact] public async Task AdminActionsWorkOnTheLoopbackPortAndNeverOnThePublicOne()
    {
        Skip.If(Exe == null, "GHOST_RELAY_EXE not provided");
        int pub = FreePort(), adm = FreePort();
        using var relay = new RelayHost(Exe!, pub, adm, Token);
        relay.Start();
        Assert.True(await relay.WaitHealthyAsync(TimeSpan.FromSeconds(15)), relay.Tail);
        using var admin = new RelayAdminClient(adm, Token);

        var code = await admin.CreateInviteAsync();
        Assert.False(string.IsNullOrWhiteSpace(code));
        var users = await admin.GetUsersAsync();
        Assert.Empty(users.Users); Assert.True(users.RecordIp); Assert.Equal(1, users.UnusedInvites);

        using var http = new HttpClient();
        var req = new HttpRequestMessage(HttpMethod.Post, $"http://127.0.0.1:{pub}/v1/admin/invites");
        req.Headers.Authorization = new("Bearer", Token);
        using (var r = await http.SendAsync(req)) Assert.Equal(HttpStatusCode.NotFound, r.StatusCode);
        using (var r = await http.GetAsync($"http://127.0.0.1:{adm}/v1/register")) Assert.True(r.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.MethodNotAllowed);
        using var bad = new RelayAdminClient(adm, "wrong-token-wrong-token-wrong-token-wrong");
        await Assert.ThrowsAnyAsync<Exception>(() => bad.CreateInviteAsync());
    }

    [SkippableFact] public async Task SnapshotSurvivesARestartThroughTheEncryptedVault()
    {
        Skip.If(Exe == null, "GHOST_RELAY_EXE not provided");
        var dir = Path.Combine(Path.GetTempPath(), "gi-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "vault.bin");
        try
        {
            string snapshot;
            using (var v = Vault.Create(path, "correct horse battery", 100_000))
            {
                int pub = FreePort(), adm = FreePort();
                using var relay = new RelayHost(Exe!, pub, adm, v.Data.AdminToken); relay.Start();
                Assert.True(await relay.WaitHealthyAsync(TimeSpan.FromSeconds(15)), relay.Tail);
                using var admin = new RelayAdminClient(adm, v.Data.AdminToken);
                await admin.CreateInviteAsync(); await admin.CreateInviteAsync();
                snapshot = await admin.ExportAsync(); v.Data.Snapshot = snapshot; v.Save();
            }
            using var v2 = Vault.Open(path, "correct horse battery");
            int pub2 = FreePort(), adm2 = FreePort();
            using var relay2 = new RelayHost(Exe!, pub2, adm2, v2.Data.AdminToken); relay2.Start();
            Assert.True(await relay2.WaitHealthyAsync(TimeSpan.FromSeconds(15)), relay2.Tail);
            using var admin2 = new RelayAdminClient(adm2, v2.Data.AdminToken);
            Assert.True(await admin2.ImportAsync(v2.Data.Snapshot!));
            Assert.Equal(2, (await admin2.GetUsersAsync()).UnusedInvites);
            Assert.False(await admin2.ImportAsync(v2.Data.Snapshot!), "a relay that already has data must refuse the import");
            Assert.DoesNotContain("invites", System.Text.Encoding.Latin1.GetString(File.ReadAllBytes(path)));
        }
        finally { try { Directory.Delete(dir, true); } catch (IOException) { } }
    }

    [SkippableFact] public async Task StoppingTheHostStopsTheRelay()
    {
        Skip.If(Exe == null, "GHOST_RELAY_EXE not provided");
        int pub = FreePort(), adm = FreePort();
        var relay = new RelayHost(Exe!, pub, adm, Token); relay.Start();
        Assert.True(await relay.WaitHealthyAsync(TimeSpan.FromSeconds(15)));
        relay.Stop(); Assert.False(relay.Running);
        await Task.Delay(500);
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
        await Assert.ThrowsAnyAsync<Exception>(() => http.GetAsync($"http://127.0.0.1:{pub}/healthz"));
    }
}

public class WindowTests
{
    [SkippableFact] public void EveryAppWindowIsExcludedFromScreenCapture()
    {
        Skip.IfNot(OperatingSystem.IsWindows(), "Windows only");
        SecureForm f;
        try { f = new SecureForm(); f.Show(); System.Windows.Forms.Application.DoEvents(); }
        catch (Exception e) { throw new Xunit.Sdk.XunitException("could not create a window: " + e.Message); }
        using (f)
        {
            Skip.IfNot(f.IsHandleCreated, "no window handle in this session");
            var a = Native.GetAffinity(f.Handle);
            Assert.True(a == Native.WDA_EXCLUDEFROMCAPTURE || a == Native.WDA_MONITOR, $"display affinity was 0x{a:X}");
            Assert.True(f.CaptureExcluded);
        }
    }
}

public class DialogLayoutTests
{
    [SkippableTheory]
    [InlineData(1.0f)] [InlineData(1.5f)] [InlineData(2.0f)]
    public void FirstRunDialogShowsAllContentAtAnyTextSize(float scale)
    {
        Skip.IfNot(OperatingSystem.IsWindows(), "Windows only");
        using var d = new PasswordDialog("Create the admin password",
            "First run. Choose the admin password. It protects everything this app stores on this PC and is asked before every action. If you forget it there is NO recovery: the encrypted data cannot be opened.", true);
        d.Font = new System.Drawing.Font(d.Font.FontFamily, d.Font.Size * scale);
        d.Show(); System.Windows.Forms.Application.DoEvents();
        Skip.IfNot(d.IsHandleCreated, "no window handle in this session");
        var need = d.Content.PreferredSize;
        Assert.True(d.ClientSize.Height >= need.Height, $"window {d.ClientSize} is smaller than its content {need}");
        Assert.True(d.ClientSize.Width >= need.Width, $"window {d.ClientSize} is narrower than its content {need}");
        Assert.True(d.Content.Bottom <= d.ClientSize.Height + 1);
    }
}
