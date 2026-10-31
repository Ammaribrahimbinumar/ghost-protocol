package com.ghostprotocol.app.background

import android.app.job.JobInfo
import android.app.job.JobScheduler
import android.content.ComponentName
import android.content.Context
import com.ghostprotocol.app.messaging.AppController
import com.ghostprotocol.app.messaging.Phase
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Periodic check of the relay while the app is closed. There is no push service (that would tell Google about
 * delivery timing), so Android runs this roughly every 15 minutes or later (battery saver and Doze can delay
 * it much more). It is NOT instant. Incoming messages are decrypted and stored; only a generic notification is shown.
 */
object BackgroundCheck {
    const val JOB_ID = 4711
    private const val PREFS = "bg_check"            // not secret: just on/off and "asked once"

    private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    fun isEnabled(ctx: Context): Boolean = prefs(ctx).getBoolean("enabled", true)
    fun setEnabled(ctx: Context, on: Boolean) { prefs(ctx).edit().putBoolean("enabled", on).apply(); if (on) schedule(ctx) else cancel(ctx) }
    fun wasAsked(ctx: Context): Boolean = prefs(ctx).getBoolean("asked", false)
    fun markAsked(ctx: Context) { prefs(ctx).edit().putBoolean("asked", true).apply() }

    fun schedule(ctx: Context) {
        val js = ctx.getSystemService(JobScheduler::class.java) ?: return
        if (js.getPendingJob(JOB_ID) != null) return
        val component = ComponentName(ctx, CheckJobService::class.java)
        fun build(persisted: Boolean) = JobInfo.Builder(JOB_ID, component)
            .setPeriodic(15 * 60_000L).setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY).setPersisted(persisted).build()
        try { js.schedule(build(true)) } catch (e: SecurityException) { js.schedule(build(false)) }
    }

    fun cancel(ctx: Context) { ctx.getSystemService(JobScheduler::class.java)?.cancel(JOB_ID) }

    /** Poll once and, if something arrived while the app is not on screen, post the generic notification. Returns messages received. */
    suspend fun run(ctx: Context, controller: AppController, foreground: Boolean): Int {
        withTimeoutOrNull(20_000) { controller.phase.first { it != Phase.Loading } }
        if (controller.phase.value != Phase.Ready) return 0
        val received = controller.pollOnce()
        if (received > 0 && !foreground && isEnabled(ctx)) Notifier.post(ctx)
        return received
    }
}
