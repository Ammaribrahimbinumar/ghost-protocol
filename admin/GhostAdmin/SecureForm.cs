using GhostAdmin.Core;

namespace GhostAdmin;

/// <summary>Every window of the app derives from this so none of them can be screenshotted or screen-recorded.</summary>
public class SecureForm : Form
{
    public bool CaptureExcluded { get; private set; }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        CaptureExcluded = Native.ExcludeFromCapture(Handle);
    }
}
