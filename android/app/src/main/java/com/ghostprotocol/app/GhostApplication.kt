package com.ghostprotocol.app

import android.app.Application
import com.ghostprotocol.app.messaging.AppController

/**
 * Holds the single real-profile [AppController] for the whole process. The activity and the background
 * check must share one instance: two live clients would each hold their own copy of the ratchet state and
 * overwrite each other's saved state.
 */
class GhostApplication : Application() {
    val controller: AppController by lazy { AppController(this).also { it.start() } }

    /** True while the activity is visible. The background check posts no notification then. */
    @Volatile var inForeground: Boolean = false
}
