package com.ghostprotocol.app.background

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import com.ghostprotocol.app.MainActivity
import com.ghostprotocol.app.R

/**
 * The only notification the app ever posts. It is deliberately generic: no sender, no text, no count, no
 * actions, and one fixed id so repeats replace each other instead of piling up.
 */
object Notifier {
    const val CHANNEL = "updates"
    const val ID = 1
    const val TITLE = "Calculator"
    const val TEXT = "Calculator got an update"

    fun post(ctx: Context): Boolean {
        val nm = ctx.getSystemService(NotificationManager::class.java) ?: return false
        if (!nm.areNotificationsEnabled()) return false
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL, "Updates", NotificationManager.IMPORTANCE_DEFAULT).apply {
                setShowBadge(false)
                lockscreenVisibility = Notification.VISIBILITY_PUBLIC   // the text is generic, so nothing to hide
            },
        )
        val open = PendingIntent.getActivity(
            ctx, 0, Intent(ctx, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val n = Notification.Builder(ctx, CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_calc)
            .setContentTitle(TITLE).setContentText(TEXT)
            .setAutoCancel(true).setOnlyAlertOnce(true)
            .setVisibility(Notification.VISIBILITY_PUBLIC)
            .setContentIntent(open)
            .build()
        nm.notify(ID, n)
        return true
    }
}
