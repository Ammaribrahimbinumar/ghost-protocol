using System.Diagnostics;
using System.Runtime.InteropServices;

namespace GhostAdmin.Core;

public static class Native
{
    public const uint WDA_NONE = 0x0, WDA_MONITOR = 0x1, WDA_EXCLUDEFROMCAPTURE = 0x11;

    [DllImport("user32.dll", SetLastError = true)] private static extern bool SetWindowDisplayAffinity(IntPtr hwnd, uint affinity);
    [DllImport("user32.dll", SetLastError = true)] private static extern bool GetWindowDisplayAffinity(IntPtr hwnd, out uint affinity);

    /// <summary>
    /// Makes screenshots, screen recordings and screen sharing show this window as black or hide it
    /// (Windows 10 version 2004 and later; older versions fall back to a black rectangle). It does not stop a camera pointed at the monitor.
    /// </summary>
    public static bool ExcludeFromCapture(IntPtr hwnd)
    {
        try { return SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE) || SetWindowDisplayAffinity(hwnd, WDA_MONITOR); }
        catch (Exception) { return false; }
    }

    public static uint GetAffinity(IntPtr hwnd) => GetWindowDisplayAffinity(hwnd, out var a) ? a : uint.MaxValue;
}

/// <summary>Ties child processes to this app: if the app dies, Windows ends the relay and the tunnel too.</summary>
internal static class JobObject
{
    [StructLayout(LayoutKind.Sequential)] private struct BasicLimit
    {
        public long PerProcessUserTimeLimit, PerJobUserTimeLimit; public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize; public uint ActiveProcessLimit;
        public UIntPtr Affinity; public uint PriorityClass, SchedulingClass;
    }
    [StructLayout(LayoutKind.Sequential)] private struct IoCounters { public ulong a, b, c, d, e, f; }
    [StructLayout(LayoutKind.Sequential)] private struct ExtendedLimit
    {
        public BasicLimit Basic; public IoCounters Io; public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr CreateJobObject(IntPtr attrs, string? name);
    [DllImport("kernel32.dll")] private static extern bool SetInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint len);
    [DllImport("kernel32.dll")] private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    private static readonly IntPtr Job = Create();
    private static IntPtr Create()
    {
        try
        {
            var h = CreateJobObject(IntPtr.Zero, null);
            var info = new ExtendedLimit(); info.Basic.LimitFlags = 0x2000; // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            int len = Marshal.SizeOf<ExtendedLimit>();
            var ptr = Marshal.AllocHGlobal(len);
            try { Marshal.StructureToPtr(info, ptr, false); SetInformationJobObject(h, 9, ptr, (uint)len); }
            finally { Marshal.FreeHGlobal(ptr); }
            return h;
        }
        catch (Exception) { return IntPtr.Zero; }
    }
    public static void Assign(Process p) { try { if (Job != IntPtr.Zero) AssignProcessToJobObject(Job, p.Handle); } catch (Exception) { } }
}
