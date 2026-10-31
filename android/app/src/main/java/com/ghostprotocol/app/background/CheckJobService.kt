package com.ghostprotocol.app.background

import android.app.job.JobParameters
import android.app.job.JobService
import com.ghostprotocol.app.GhostApplication
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class CheckJobService : JobService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var job: Job? = null

    override fun onStartJob(params: JobParameters): Boolean {
        val app = application as GhostApplication
        job = scope.launch {
            try { BackgroundCheck.run(applicationContext, app.controller, app.inForeground) }
            finally { jobFinished(params, false) }
        }
        return true
    }

    override fun onStopJob(params: JobParameters): Boolean { job?.cancel(); return true }   // ask Android to retry later
}
