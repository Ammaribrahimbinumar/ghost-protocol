using GhostAdmin.Core;

namespace GhostAdmin;

internal static class Program
{
    public static string VaultPath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "GhostAdmin", "vault.bin");

    [STAThread]
    private static void Main()
    {
        ApplicationConfiguration.Initialize();
        Vault? vault = null;
        if (!Vault.Exists(VaultPath))
        {
            using var d = new PasswordDialog("Create the admin password",
                "First run. Choose the admin password. It protects everything this app stores on this PC and is asked before every action. If you forget it there is NO recovery: the encrypted data cannot be opened.", true);
            if (d.ShowDialog() != DialogResult.OK) return;
            vault = Vault.Create(VaultPath, d.Password!);
        }
        else
        {
            int fails = 0;
            while (vault == null)
            {
                using var d = new PasswordDialog("Unlock Ghost admin", "Enter the admin password.", false);
                if (d.ShowDialog() != DialogResult.OK) return;
                try { vault = Vault.Open(VaultPath, d.Password!); }
                catch (VaultException ex)
                {
                    fails++;
                    MessageBox.Show(ex.Message, "Cannot open", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    Thread.Sleep(Math.Min(15, 1 << Math.Min(fails, 4)) * 1000);
                }
            }
        }
        using (vault) Application.Run(new MainForm(vault));
    }
}
