package com.ghostprotocol.app.security

import android.app.Activity
import android.os.Build
import android.view.WindowManager

/**
 * Window-level hardening. Call before setContent().
 *
 * - FLAG_SECURE: blocks screenshots, standard screen recording and the recent-apps thumbnail.
 * - setRecentsScreenshotEnabled(false): extra recents protection on API 33+.
 * - setHideOverlayWindows(true): asks Android to hide other apps' overlay windows (API 31+,
 *   needs the HIDE_OVERLAY_WINDOWS permission, declared in the manifest).
 * - filterTouchesWhenObscured: drops touches delivered while another window covers ours
 *   (tapjacking protection).
 *
 * These are best-effort app-level protections. Rooted or modified systems, screen-reading
 * malware, HDMI/external capture and a phone camera all bypass them.
 *
 * NOT COMPILED OR RUN on a device.
 */
object SecureWindow {
    fun apply(activity: Activity) {
        val window = activity.window
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            activity.setRecentsScreenshotEnabled(false)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            window.setHideOverlayWindows(true)
        }
        window.decorView.filterTouchesWhenObscured = true
    }
}
