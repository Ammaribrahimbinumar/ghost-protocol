using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace GhostAdmin.Core;

public sealed class UserRow
{
    [JsonPropertyName("username")] public string Username { get; set; } = "";
    [JsonPropertyName("created")] public long Created { get; set; }
    [JsonPropertyName("last_seen")] public long LastSeen { get; set; }
    [JsonPropertyName("ip")] public string? Ip { get; set; }
    [JsonPropertyName("queued")] public int Queued { get; set; }
}

public sealed class UsersResult
{
    [JsonPropertyName("users")] public List<UserRow> Users { get; set; } = new();
    [JsonPropertyName("record_ip")] public bool RecordIp { get; set; }
    [JsonPropertyName("unused_invites")] public int UnusedInvites { get; set; }
}

/// <summary>Talks to the relay's loopback-only admin listener. The bearer token never leaves this machine.</summary>
public sealed class RelayAdminClient : IDisposable
{
    private readonly HttpClient _http;
    public RelayAdminClient(int adminPort, string token)
    {
        _http = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{adminPort}"), Timeout = TimeSpan.FromSeconds(15) };
        _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
    }

    public async Task<string> CreateInviteAsync()
    {
        using var r = await _http.PostAsync("/v1/admin/invites", null);
        if ((int)r.StatusCode != 201) throw new InvalidOperationException($"The relay refused ({(int)r.StatusCode}).");
        using var doc = JsonDocument.Parse(await r.Content.ReadAsStringAsync());
        return doc.RootElement.GetProperty("invite").GetString() ?? throw new InvalidOperationException("No invite in reply.");
    }

    public async Task<UsersResult> GetUsersAsync()
    {
        using var r = await _http.GetAsync("/v1/admin/users");
        r.EnsureSuccessStatusCode();
        return JsonSerializer.Deserialize<UsersResult>(await r.Content.ReadAsStringAsync()) ?? new UsersResult();
    }

    public async Task<string> ExportAsync()
    {
        using var r = await _http.GetAsync("/v1/admin/export");
        r.EnsureSuccessStatusCode();
        return await r.Content.ReadAsStringAsync();
    }

    /// <summary>True if imported; false if the relay already had data (409).</summary>
    public async Task<bool> ImportAsync(string json)
    {
        using var r = await _http.PostAsync("/v1/admin/import", new StringContent(json, Encoding.UTF8, "application/json"));
        if ((int)r.StatusCode == 204) return true;
        if ((int)r.StatusCode == 409) return false;
        throw new InvalidOperationException($"Import refused ({(int)r.StatusCode}).");
    }

    public void Dispose() => _http.Dispose();
}
