using GhostAdmin.Core;

namespace GhostAdmin;

/// <summary>Asks for the admin password (twice when creating it). The text box masks input.</summary>
public sealed class PasswordDialog : SecureForm
{
    private readonly TextBox _pw = new() { UseSystemPasswordChar = true, Width = 400 };
    private readonly TextBox _pw2 = new() { UseSystemPasswordChar = true, Width = 400 };
    private readonly Label _note = new() { AutoSize = true, MaximumSize = new Size(420, 0), ForeColor = Color.Firebrick };
    private readonly bool _confirm;
    public string? Password { get; private set; }
    public Control Content => Controls[0];

    public PasswordDialog(string title, string message, bool confirm, string? note = null)
    {
        _confirm = confirm;
        Text = title; FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = false; MinimizeBox = false;
        StartPosition = FormStartPosition.CenterParent; ShowInTaskbar = false;
        // The window grows to fit its content (long first-run text, large fonts, high-DPI screens).
        AutoSize = true; AutoSizeMode = AutoSizeMode.GrowAndShrink; MinimumSize = new Size(400, 0);
        var panel = new FlowLayoutPanel { AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, FlowDirection = FlowDirection.TopDown, WrapContents = false, Padding = new Padding(14) };
        panel.Controls.Add(new Label { Text = message, AutoSize = true, MaximumSize = new Size(420, 0) });
        panel.Controls.Add(_pw);
        if (confirm) { panel.Controls.Add(new Label { Text = "Type it again:", AutoSize = true }); panel.Controls.Add(_pw2); }
        _note.Text = note ?? ""; panel.Controls.Add(_note);
        var ok = new Button { Text = "OK", DialogResult = DialogResult.None, Width = 90 };
        var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Width = 90 };
        ok.Click += (_, _) => Accept();
        var row = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.LeftToRight };
        row.Controls.Add(ok); row.Controls.Add(cancel); panel.Controls.Add(row);
        Controls.Add(panel); AcceptButton = ok; CancelButton = cancel;
        FormClosed += (_, _) => { _pw.Clear(); _pw2.Clear(); };
    }

    private void Accept()
    {
        if (_confirm)
        {
            if (_pw.Text.Length < Vault.MinPasswordLength) { _note.Text = $"Use at least {Vault.MinPasswordLength} characters. A long phrase is best."; return; }
            if (_pw.Text != _pw2.Text) { _note.Text = "The two entries do not match."; return; }
        }
        else if (_pw.Text.Length == 0) { _note.Text = "Enter the password."; return; }
        Password = _pw.Text; DialogResult = DialogResult.OK;
    }

    /// <summary>Re-checks the admin password before an action. Returns true only for the right password.</summary>
    public static bool Confirm(IWin32Window owner, PasswordGate gate, string action)
    {
        string? note = null;
        while (true)
        {
            using var d = new PasswordDialog("Admin password", $"Enter the admin password to {action}.", false, note);
            if (d.ShowDialog(owner) != DialogResult.OK) return false;
            if (gate.TryVerify(d.Password!)) return true;
            var wait = (int)Math.Ceiling(gate.Remaining.TotalSeconds);
            note = wait > 0 ? $"Wrong password. Wait {wait} seconds before trying again." : "Wrong password.";
        }
    }
}
