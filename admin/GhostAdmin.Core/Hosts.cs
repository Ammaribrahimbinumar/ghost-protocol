using System.Diagnostics;

namespace GhostAdmin.Core;

/// <summary>A child program whose output is drained (so it never blocks) and whose last lines are kept for error messages.</summary>
public abstract class ChildHost : IDisposable
{
    protected Process? Proc;
    private readonly Queue<string> _tail = new();
    public event Action<string>? Line;
    public bool Running => Proc is { HasExited: false };
    public string Tail { get { lock (_tail) return string.Join("\n", _tail); } }

    protected void Launch(string exe, IEnumerable<string> args, IDictionary<string, string>? env = null)
    {
        if (Running) throw new InvalidOperationException("Already running.");
        lock (_tail) _tail.Clear();
        var psi = new ProcessStartInfo(exe) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in args) psi.ArgumentList.Add(a);
        if (env != null) foreach (var kv in env) psi.Environment[kv.Key] = kv.Value;
        var p = new Process { StartInfo = psi, EnableRaisingEvents = true };
        void OnData(object _, DataReceivedEventArgs e)
        {
            if (e.Data == null) return;
            lock (_tail) { _tail.Enqueue(e.Data); while (_tail.Count > 15) _tail.Dequeue(); }
            Line?.Invoke(e.Data);
        }
        p.OutputDataReceived += OnData; p.ErrorDataReceived += OnData;
        p.Start(); JobObject.Assign(p);
        p.BeginOutputReadLine(); p.BeginErrorReadLine();
        Proc = p;
    }

    public void Stop()
    {
        var p = Proc; Proc = null;
        if (p == null) return;
        try { if (!p.HasExited) { p.Kill(entireProcessTree: true); p.WaitForExit(3000); } } catch (Exception) { }
        p.Dispose();
    }

    public void Dispose() => Stop();
}

/// <summary>The relay: public port for users, a separate loopback-only port for admin actions, addresses kept in memory only.</summary>
public sealed class RelayHost : ChildHost
{
    public int Port { get; }
    public int AdminPort { get; }
    private readonly string _exe, _token;

    public RelayHost(string exe, int port, int adminPort, string token) { _exe = exe; Port = port; AdminPort = adminPort; _token = token; }

    public void Start()
    {
        Launch(_exe, new[]
        {
            "-insecure-dev", "-addr", $"127.0.0.1:{Port}", "-admin-addr", $"127.0.0.1:{AdminPort}",
            "-record-ip", "-trust-cf-header", "-ip-rate", "5", "-ip-burst", "100",
        }, new Dictionary<string, string> { ["GHOST_ADMIN_TOKEN"] = _token });
    }

    public async Task<bool> WaitHealthyAsync(TimeSpan timeout)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
        var end = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < end)
        {
            if (!Running) return false;
            try { using var r = await http.GetAsync($"http://127.0.0.1:{Port}/healthz"); if ((int)r.StatusCode == 204) return true; } catch (Exception) { }
            await Task.Delay(250);
        }
        return false;
    }
}

/// <summary>Cloudflare quick tunnel to the relay's PUBLIC port only (never the admin port).</summary>
public sealed class TunnelHost : ChildHost
{
    public string? Url { get; private set; }
    public event Action<string>? UrlFound;
    public TunnelHost() { Line += OnLine; }

    public static string? FindExecutable(string? configured)
    {
        var candidates = new List<string>();
        if (!string.IsNullOrWhiteSpace(configured)) candidates.Add(configured!);
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
            candidates.Add(Path.Combine(dir.Trim('"'), "cloudflared.exe"));
        var pf = Environment.GetEnvironmentVariable("ProgramFiles"); var pf86 = Environment.GetEnvironmentVariable("ProgramFiles(x86)");
        var local = Environment.GetEnvironmentVariable("LOCALAPPDATA");
        if (pf != null) candidates.Add(Path.Combine(pf, "cloudflared", "cloudflared.exe"));
        if (pf86 != null) candidates.Add(Path.Combine(pf86, "cloudflared", "cloudflared.exe"));
        if (local != null) candidates.Add(Path.Combine(local, "Microsoft", "WinGet", "Links", "cloudflared.exe"));
        return candidates.FirstOrDefault(File.Exists);
    }

    public void Start(string exe, int relayPort, bool http2)
    {
        Url = null;
        var args = new List<string> { "tunnel", "--no-autoupdate", "--url", $"http://127.0.0.1:{relayPort}" };
        if (http2) { args.Add("--protocol"); args.Add("http2"); }
        Launch(exe, args);
    }

    private void OnLine(string line)
    {
        if (Url != null) return;
        var u = TunnelUrlParser.TryParse(line);
        if (u == null) return;
        Url = u; UrlFound?.Invoke(u);
    }

    public async Task<bool> WaitForUrlAsync(TimeSpan timeout)
    {
        var end = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < end) { if (Url != null) return true; if (!Running) return false; await Task.Delay(200); }
        return Url != null;
    }
}

/// <summary>Keeps trying to bring the tunnel up. Cloudflare's tunnel-creation request fails now and then on some connections, so one failure is not the end.</summary>
public static class TunnelRetry
{
    /// <summary>
    /// Calls <paramref name="attempt"/> (argument: use the HTTP/2 connection type) up to <paramref name="maxAttempts"/> times,
    /// alternating the connection type and waiting between tries. Returns the attempt number that worked, or 0.
    /// </summary>
    public static async Task<int> RunAsync(Func<bool, Task<bool>> attempt, int maxAttempts, TimeSpan pause,
        Action<int, int>? progress = null, CancellationToken cancel = default)
    {
        for (int i = 1; i <= maxAttempts; i++)
        {
            cancel.ThrowIfCancellationRequested();
            progress?.Invoke(i, maxAttempts);
            if (await attempt(i % 2 == 0)) return i;
            if (i < maxAttempts) await Task.Delay(pause, cancel);
        }
        return 0;
    }
}
