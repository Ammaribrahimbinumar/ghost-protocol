using GhostAdmin.Core;

namespace GhostAdmin;

public sealed class MainForm : SecureForm
{
    private readonly Vault _vault;
    private readonly PasswordGate _gate;
    private RelayHost? _relay;
    private TunnelHost? _tunnel;
    private RelayAdminClient? _admin;
    private string _lastSignature = "";
    private bool _busy;
    private DateTime _usersVisibleUntil = DateTime.MinValue;

    private readonly Label _status = new() { AutoSize = true, MaximumSize = new Size(700, 0) };
    private readonly TextBox _address = new() { ReadOnly = true, Width = 520 };
    private readonly TextBox _invite = new() { ReadOnly = true, Width = 320, Font = new Font(FontFamily.GenericMonospace, 10f) };
    private readonly Button _start = new() { Text = "Start server + tunnel", Width = 170 };
    private readonly Button _stop = new() { Text = "Stop", Width = 80, Enabled = false };
    private readonly Button _copyAddress = new() { Text = "Copy address", Width = 110 };
    private readonly Button _newInvite = new() { Text = "Request invite code", Width = 170, Enabled = false };
    private readonly Button _copyInvite = new() { Text = "Copy invite message", Width = 150 };
    private readonly Button _showUsers = new() { Text = "Show registered users", Width = 170, Enabled = false };
    private readonly Button _hideUsers = new() { Text = "Hide", Width = 70, Visible = false };
    private readonly Label _usersNote = new() { AutoSize = true, MaximumSize = new Size(700, 0), Visible = false };
    private readonly DataGridView _grid = new()
    {
        Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false, RowHeadersVisible = false,
        AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill, SelectionMode = DataGridViewSelectionMode.FullRowSelect, Visible = false,
    };
    private readonly System.Windows.Forms.Timer _tick = new() { Interval = 5000 };

    public MainForm(Vault vault)
    {
        _vault = vault; _gate = new PasswordGate(vault);
        Text = "Ghost admin"; ClientSize = new Size(760, 560); MinimumSize = new Size(640, 480); StartPosition = FormStartPosition.CenterScreen;

        var top = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, FlowDirection = FlowDirection.TopDown, WrapContents = false, Padding = new Padding(12) };
        top.Controls.Add(_status);
        var r1 = Row(_start, _stop); top.Controls.Add(r1);
        top.Controls.Add(new Label { Text = "Relay address (give this to your users):", AutoSize = true });
        top.Controls.Add(Row(_address, _copyAddress));
        top.Controls.Add(Row(_newInvite));
        top.Controls.Add(new Label { Text = "Invitation code (single use):", AutoSize = true });
        top.Controls.Add(Row(_invite, _copyInvite));
        top.Controls.Add(Row(_showUsers, _hideUsers));
        top.Controls.Add(_usersNote);
        Controls.Add(_grid); Controls.Add(top);

        _grid.Columns.Add("u", "Username"); _grid.Columns.Add("ip", "Address (last seen)");
        _grid.Columns.Add("seen", "Last seen"); _grid.Columns.Add("created", "Registered"); _grid.Columns.Add("q", "Waiting messages");

        _start.Click += async (_, _) => await OnStart();
        _stop.Click += async (_, _) => await OnStop();
        _newInvite.Click += async (_, _) => await OnInvite();
        _showUsers.Click += async (_, _) => await OnShowUsers();
        _hideUsers.Click += (_, _) => HideUsers();
        _copyAddress.Click += (_, _) => CopySensitive(_address.Text);
        _copyInvite.Click += (_, _) => { if (_invite.Text.Length > 0) CopySensitive(InviteMessage.Build(_address.Text.Length > 0 ? _address.Text : "(start the tunnel first)", _invite.Text)); };
        _tick.Tick += async (_, _) => await OnTick();
        FormClosing += OnClosing;
        SetStatus("Stopped. Click \"Start server + tunnel\".");
    }

    private static FlowLayoutPanel Row(params Control[] c)
    {
        var p = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Margin = new Padding(0, 4, 0, 4) };
        foreach (var x in c) p.Controls.Add(x);
        return p;
    }

    private void SetStatus(string s) => _status.Text = s;
    private bool Confirm(string action) => PasswordDialog.Confirm(this, _gate, action);
    private static string AppDir => Path.GetDirectoryName(Environment.ProcessPath) ?? AppContext.BaseDirectory;

    private async Task OnStart()
    {
        if (_busy || (_relay?.Running ?? false)) return;
        if (!Confirm("start the server and the Cloudflare tunnel")) return;
        _busy = true; _start.Enabled = false;
        try
        {
            var relayExe = Path.Combine(AppDir, "ghost-relay.exe");
            if (!File.Exists(relayExe)) throw new InvalidOperationException("ghost-relay.exe must be in the same folder as GhostAdmin.exe.");
            var cf = TunnelHost.FindExecutable(_vault.Data.CloudflaredPath)
                ?? throw new InvalidOperationException("Cloudflare's cloudflared program was not found. Install it once with:  winget install --id Cloudflare.cloudflared  and then start again.");

            SetStatus("Starting the relay...");
            _relay = new RelayHost(relayExe, _vault.Data.RelayPort, _vault.Data.AdminPort, _vault.Data.AdminToken);
            _relay.Start();
            if (!await _relay.WaitHealthyAsync(TimeSpan.FromSeconds(12)))
                throw new InvalidOperationException("The relay did not start. Is another program using port " + _vault.Data.RelayPort + "? " + _relay.Tail);
            _admin = new RelayAdminClient(_vault.Data.AdminPort, _vault.Data.AdminToken);
            if (!string.IsNullOrEmpty(_vault.Data.Snapshot)) await _admin.ImportAsync(_vault.Data.Snapshot!);

            SetStatus("Starting the Cloudflare tunnel (this can take up to a minute)...");
            _tunnel = new TunnelHost();
            _tunnel.Start(cf, _vault.Data.RelayPort, http2: false);
            if (!await _tunnel.WaitForUrlAsync(TimeSpan.FromSeconds(30)))
            {
                _tunnel.Stop(); SetStatus("Retrying the tunnel with another connection type...");
                _tunnel.Start(cf, _vault.Data.RelayPort, http2: true);
                if (!await _tunnel.WaitForUrlAsync(TimeSpan.FromSeconds(40)))
                    throw new InvalidOperationException("The tunnel did not give an address. Check your internet or turn off any VPN, then try again.\n" + _tunnel.Tail);
            }
            _address.Text = _tunnel.Url!;
            SetStatus("Running. The relay is on and the tunnel is up. The tunnel address changes every time you start it.");
            _stop.Enabled = _newInvite.Enabled = _showUsers.Enabled = true;
            await SaveSnapshotIfChanged(force: true);
            _tick.Start();
        }
        catch (Exception ex)
        {
            await StopAll(save: false);
            SetStatus("Could not start: " + ex.Message);
            _start.Enabled = true;
        }
        finally { _busy = false; }
    }

    private async Task OnStop()
    {
        if (_busy) return;
        if (!Confirm("stop the server and the tunnel")) return;
        _busy = true;
        try { await StopAll(save: true); SetStatus("Stopped. Users cannot reach the relay now, and addresses seen so far are forgotten."); }
        finally { _busy = false; }
    }

    private async Task StopAll(bool save)
    {
        _tick.Stop();
        if (save) { try { await SaveSnapshotIfChanged(force: true); } catch (Exception) { } }
        _tunnel?.Stop(); _tunnel = null;
        _relay?.Stop(); _relay = null;
        _admin?.Dispose(); _admin = null;
        _address.Clear(); HideUsers();
        _start.Enabled = true; _stop.Enabled = _newInvite.Enabled = _showUsers.Enabled = false;
        _lastSignature = "";
    }

    private async Task OnInvite()
    {
        if (_admin == null || _busy) return;
        if (!Confirm("create a new invitation code")) return;
        try
        {
            _invite.Text = await _admin.CreateInviteAsync();
            await SaveSnapshotIfChanged(force: true);
        }
        catch (Exception ex) { SetStatus("Could not create a code: " + ex.Message); }
    }

    private async Task OnShowUsers()
    {
        if (_admin == null || _busy) return;
        if (!Confirm("show the registered users and their addresses")) return;
        _usersVisibleUntil = DateTime.UtcNow.AddMinutes(2);
        _grid.Visible = _hideUsers.Visible = _usersNote.Visible = true;
        await RefreshUsers();
    }

    private void HideUsers()
    {
        _usersVisibleUntil = DateTime.MinValue;
        _grid.Rows.Clear(); _grid.Visible = _hideUsers.Visible = _usersNote.Visible = false;
    }

    private static string When(long unix) => unix <= 0 ? "-" : DateTimeOffset.FromUnixTimeSeconds(unix).LocalDateTime.ToString("yyyy-MM-dd HH:mm");

    private async Task RefreshUsers()
    {
        if (_admin == null) return;
        var r = await _admin.GetUsersAsync();
        _grid.Rows.Clear();
        foreach (var u in r.Users) _grid.Rows.Add(u.Username, string.IsNullOrEmpty(u.Ip) ? "(not seen since the relay started)" : u.Ip, When(u.LastSeen), When(u.Created), u.Queued);
        _usersNote.Text = $"{r.Users.Count} registered, {r.UnusedInvites} invitation codes unused. Addresses are held in the relay's memory only and are lost when you stop it. Users connecting through the tunnel show the address Cloudflare reports. This list hides itself after 2 minutes.";
    }

    private async Task OnTick()
    {
        if (_admin == null || _busy) return;
        if (_relay is { Running: false } || _tunnel is { Running: false })
        {
            await StopAll(save: false); SetStatus("The relay or the tunnel stopped unexpectedly. Click Start to run it again."); return;
        }
        try
        {
            await SaveSnapshotIfChanged(force: false);
            if (_grid.Visible) { if (DateTime.UtcNow > _usersVisibleUntil) HideUsers(); else await RefreshUsers(); }
        }
        catch (Exception) { /* transient; try again on the next tick */ }
    }

    /// <summary>Keeps the encrypted copy of the relay's accounts current, so a crash or reboot never locks users out.</summary>
    private async Task SaveSnapshotIfChanged(bool force)
    {
        if (_admin == null) return;
        var users = await _admin.GetUsersAsync();
        var sig = users.Users.Count + ":" + users.UnusedInvites;
        if (!force && sig == _lastSignature) return;
        _vault.Data.Snapshot = await _admin.ExportAsync();
        _vault.Save();
        _lastSignature = sig;
    }

    private void OnClosing(object? sender, FormClosingEventArgs e)
    {
        _tick.Stop();
        if (_relay != null || _tunnel != null)
        {
            // Save the encrypted snapshot before the relay goes away. Run off the UI thread so waiting here cannot deadlock.
            try { Task.Run(() => SaveSnapshotIfChanged(force: true)).Wait(TimeSpan.FromSeconds(5)); } catch (Exception) { }
            _tunnel?.Stop(); _relay?.Stop(); _admin?.Dispose();
        }
    }

    private static void CopySensitive(string text)
    {
        if (text.Length == 0) return;
        try
        {
            var d = new DataObject();
            d.SetText(text);
            // Ask Windows not to keep this in clipboard history or sync it to other devices.
            d.SetData("CanIncludeInClipboardHistory", new MemoryStream(BitConverter.GetBytes(0)));
            d.SetData("CanUploadToCloudClipboard", new MemoryStream(BitConverter.GetBytes(0)));
            Clipboard.SetDataObject(d, true);
        }
        catch (Exception) { try { Clipboard.SetText(text); } catch (Exception) { return; } }
        var t = new System.Windows.Forms.Timer { Interval = 60_000 };
        t.Tick += (_, _) => { t.Stop(); t.Dispose(); try { if (Clipboard.ContainsText() && Clipboard.GetText() == text) Clipboard.Clear(); } catch (Exception) { } };
        t.Start();
    }
}
