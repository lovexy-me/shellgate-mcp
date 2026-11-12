package io.shellgate.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Starts ShellGate after a reboot or an app update, when autostart is on (default on). */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) {
        val a = intent.action ?: return
        if (a != Intent.ACTION_BOOT_COMPLETED && a != Intent.ACTION_MY_PACKAGE_REPLACED) return
        if (Prefs.autostart(ctx)) SgService.start(ctx)
    }
}

object Prefs {
    private fun p(ctx: Context) = ctx.getSharedPreferences("sg", Context.MODE_PRIVATE)
    fun autostart(ctx: Context) = p(ctx).getBoolean("autostart", true)
    fun setAutostart(ctx: Context, on: Boolean) = p(ctx).edit().putBoolean("autostart", on).apply()
    fun wantRunning(ctx: Context) = p(ctx).getBoolean("run", true)
    fun setWantRunning(ctx: Context, on: Boolean) = p(ctx).edit().putBoolean("run", on).apply()
}
