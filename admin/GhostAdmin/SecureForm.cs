using GhostAdmin.Core;

namespace GhostAdmin;

/// <summary>Every window of the app derives from this so none of them can be screenshotted or screen-recorded.</summary>
public class SecureForm : Form
{
    public bool CaptureExcluded { get; private set; }

    // Scale with the screen's DPI so text is never cut off on high-resolution or enlarged-text displays.
    public SecureForm() { AutoScaleMode = AutoScaleMode.Dpi; }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        CaptureExcluded = Native.ExcludeFromCapture(Handle);
    }
}
