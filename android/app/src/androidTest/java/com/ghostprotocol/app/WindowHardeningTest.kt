package com.ghostprotocol.app

import android.view.WindowManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.core.app.ActivityScenario
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Verifies the app really sets FLAG_SECURE on its window. It does not prove capture is blocked on any given phone. */
@RunWith(AndroidJUnit4::class)
class WindowHardeningTest {
    @Test fun mainWindowHasFlagSecure() {
        ActivityScenario.launch(MainActivity::class.java).use { sc ->
            sc.onActivity { act ->
                val f = act.window.attributes.flags
                assertTrue("FLAG_SECURE must be set", f and WindowManager.LayoutParams.FLAG_SECURE != 0)
                assertTrue("touch filtering must be on", act.window.decorView.filterTouchesWhenObscured)
            }
        }
    }
}
