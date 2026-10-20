package com.ghostprotocol.app.security

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.provider.Settings
import android.view.accessibility.AccessibilityManager

enum class Severity { INFO, WARN, HIGH }

/** A finding never contains chat content; it only describes the device environment. */
data class RiskFinding(val id: String, val severity: Severity, val message: String)

data class AccessibilityServiceSummary(val label: String, val canReadScreen: Boolean)

data class RiskInputs(
    val accessibilityServices: List<AccessibilityServiceSummary>,
    val adbEnabled: Boolean,
    val developerOptionsEnabled: Boolean,
)

enum class RiskPolicy { WARN_ONLY, BLOCK_ON_HIGH }

/**
 * Best-effort environment checks before revealing chats.
 *
 * Limits, stated plainly: an ordinary app cannot reliably detect every malicious app, rooted
 * devices, or modified operating systems, and a determined attacker can hide from these checks.
 * A clean result is not proof the device is safe. Ghost_Protocol never disables or alters other
 * apps' settings; it only reports.
 */
object RiskCheck {

    /** Pure decision logic, unit-testable without Android. */
    fun evaluate(inputs: RiskInputs): List<RiskFinding> {
        val out = mutableListOf<RiskFinding>()
        for (svc in inputs.accessibilityServices) {
            if (svc.canReadScreen) {
                out += RiskFinding(
                    "a11y:${svc.label}", Severity.HIGH,
                    "Accessibility service \"${svc.label}\" can read screen content.",
                )
            } else {
                out += RiskFinding("a11y:${svc.label}", Severity.WARN, "Accessibility service \"${svc.label}\" is enabled.")
            }
        }
        if (inputs.adbEnabled) {
            out += RiskFinding("adb", Severity.WARN, "USB debugging is enabled.")
        }
        if (inputs.developerOptionsEnabled) {
            out += RiskFinding("devopts", Severity.INFO, "Developer options are enabled.")
        }
        return out
    }

    /** True when [policy] says chats must stay hidden until the findings are resolved. */
    fun blocks(findings: List<RiskFinding>, policy: RiskPolicy): Boolean =
        policy == RiskPolicy.BLOCK_ON_HIGH && findings.any { it.severity == Severity.HIGH }

    fun collect(context: Context): RiskInputs {
        val am = context.getSystemService(AccessibilityManager::class.java)
        val pm = context.packageManager
        val services = am?.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
            .orEmpty()
            .map {
                AccessibilityServiceSummary(
                    label = it.resolveInfo.loadLabel(pm).toString(),
                    canReadScreen = (it.capabilities and AccessibilityServiceInfo.CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT) != 0,
                )
            }
        val cr = context.contentResolver
        return RiskInputs(
            accessibilityServices = services,
            adbEnabled = Settings.Global.getInt(cr, Settings.Global.ADB_ENABLED, 0) == 1,
            developerOptionsEnabled = Settings.Global.getInt(cr, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1,
        )
    }

    fun scan(context: Context): List<RiskFinding> = evaluate(collect(context))
}
