using System.Text.RegularExpressions;

namespace GhostAdmin.Core;

public static class TunnelUrlParser
{
    private static readonly Regex Rx = new(@"https://([a-z0-9][a-z0-9-]*)\.trycloudflare\.com", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>Finds the quick-tunnel address in a line of cloudflared output. "api.trycloudflare.com" is Cloudflare's own service, not a tunnel.</summary>
    public static string? TryParse(string line)
    {
        foreach (Match m in Rx.Matches(line))
        {
            if (m.Groups[1].Value.Equals("api", StringComparison.OrdinalIgnoreCase)) continue;
            return m.Value.ToLowerInvariant();
        }
        return null;
    }
}

public static class InviteMessage
{
    public static string Build(string address, string code) =>
        $"Relay address: {address}\nInvitation code: {code}\n(Use it once. Enter both in the app's \"Join a relay\" screen.)";
}
