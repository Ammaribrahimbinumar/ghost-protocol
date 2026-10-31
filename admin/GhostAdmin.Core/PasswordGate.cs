namespace GhostAdmin.Core;

/// <summary>
/// Re-checks the admin password before every action and slows down guessing: after each wrong attempt the
/// wait doubles (1, 2, 4 ... capped at 60 seconds). A correct password resets it.
/// </summary>
public sealed class PasswordGate
{
    private readonly Vault _vault;
    private readonly Func<DateTime> _now;
    private int _failures;
    private DateTime _lockedUntil = DateTime.MinValue;

    public PasswordGate(Vault vault, Func<DateTime>? now = null) { _vault = vault; _now = now ?? (() => DateTime.UtcNow); }

    public TimeSpan Remaining { get { var r = _lockedUntil - _now(); return r > TimeSpan.Zero ? r : TimeSpan.Zero; } }
    public int Failures => _failures;

    /// <summary>Returns true only for the right password. While waiting out a delay it returns false without checking.</summary>
    public bool TryVerify(string password)
    {
        if (Remaining > TimeSpan.Zero) return false;
        if (_vault.CheckPassword(password)) { _failures = 0; return true; }
        _failures++;
        var seconds = Math.Min(60, 1 << Math.Min(_failures - 1, 6));
        _lockedUntil = _now().AddSeconds(seconds);
        return false;
    }
}
