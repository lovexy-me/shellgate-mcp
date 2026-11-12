package io.shellgate.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import java.io.File

/**
 * Foreground service that keeps the ShellGate binary (and, in tunnel mode, cloudflared which
 * ShellGate supervises itself) running. If the process dies it is started again with backoff.
 *
 * Files (all private to the app):
 *   files/shellgate.env   config (created on first start by the binary, or from assets/preset.env)
 *   files/logs/           state dir: audit log, cloudflared.log, admin.key, shellgate.log
 */
class SgService : Service() {

    companion object {
        const val CH = "shellgate"
        const val NOTE_ID = 1
        @Volatile var running = false
            private set
        @Volatile var pid = 0
            private set

        fun start(ctx: Context) {
            val i = Intent(ctx, SgService::class.java)
            if (Build.VERSION.SDK_INT >= 26) ctx.startForegroundService(i) else ctx.startService(i)
        }

        fun stop(ctx: Context) {
            ctx.stopService(Intent(ctx, SgService::class.java))
        }

        fun configFile(ctx: Context) = File(ctx.filesDir, "shellgate.env")
        fun stateDir(ctx: Context) = File(ctx.filesDir, "logs")

        /** First start: use the preset config shipped in the APK (personal builds), if any. */
        fun installPreset(ctx: Context) {
            val cfg = configFile(ctx)
            if (cfg.exists()) return
            try {
                ctx.assets.open("preset.env").use { inp ->
                    cfg.outputStream().use { inp.copyTo(it) }
                }
                cfg.setReadable(false, false); cfg.setReadable(true, true)
            } catch (_: Exception) {
                // no preset: the binary creates a fresh config with a new token
            }
        }
    }

    @Volatile private var wanted = false
    private var proc: Process? = null
    private var worker: Thread? = null
    private var wake: PowerManager.WakeLock? = null
    private var wifi: WifiManager.WifiLock? = null
    private var multicast: WifiManager.MulticastLock? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        val nm = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= 26) {
            nm.createNotificationChannel(NotificationChannel(CH, "ShellGate", NotificationManager.IMPORTANCE_LOW))
        }
    }

    private fun note(text: String): Notification {
        val pi = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val b = if (Build.VERSION.SDK_INT >= 26) Notification.Builder(this, CH) else @Suppress("DEPRECATION") Notification.Builder(this)
        return b.setSmallIcon(R.drawable.ic_stat)
            .setContentTitle("ShellGate")
            .setContentText(text)
            .setOngoing(true)
            .setContentIntent(pi)
            .build()
    }

    private fun updateNote(text: String) {
        getSystemService(NotificationManager::class.java).notify(NOTE_ID, note(text))
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val n = note("正在启动…")
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTE_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTE_ID, n)
        }
        if (!wanted) {
            wanted = true
            acquireLocks()
            worker = Thread({ loop() }, "shellgate-supervisor").also { it.start() }
        }
        return START_STICKY
    }

    private fun acquireLocks() {
        val pm = getSystemService(PowerManager::class.java)
        wake = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "shellgate:run").apply { setReferenceCounted(false); acquire() }
        val wm = applicationContext.getSystemService(WifiManager::class.java)
        @Suppress("DEPRECATION")
        wifi = wm.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "shellgate").apply { setReferenceCounted(false); acquire() }
        // lets the mDNS responder see multicast in lan mode
        multicast = wm.createMulticastLock("shellgate").apply { setReferenceCounted(false); acquire() }
    }

    private fun releaseLocks() {
        try { wake?.release() } catch (_: Exception) {}
        try { wifi?.release() } catch (_: Exception) {}
        try { multicast?.release() } catch (_: Exception) {}
    }

    private fun loop() {
        val lib = applicationInfo.nativeLibraryDir
        val bin = File(lib, "libshellgate.so")
        val cfd = File(lib, "libcloudflared.so")
        val state = stateDir(this).apply { mkdirs() }
        installPreset(this)
        var backoff = 2L
        while (wanted) {
            val log = File(state, "shellgate.log")
            if (log.length() > 1_000_000) log.renameTo(File(state, "shellgate.log.1"))
            val pb = ProcessBuilder(bin.absolutePath, "--env-file", configFile(this).absolutePath)
                .directory(filesDir)
                .redirectErrorStream(true)
                .redirectOutput(ProcessBuilder.Redirect.appendTo(log))
            val env = pb.environment()
            env["HOME"] = filesDir.absolutePath
            env["TMPDIR"] = cacheDir.absolutePath
            env["SHELLGATE_STATE_DIR"] = state.absolutePath
            env["SHELLGATE_CLOUDFLARED"] = cfd.absolutePath
            env["SHELLGATE_SUPERVISED"] = "android"
            env["PATH"] = "/system/bin:/system/xbin:/vendor/bin:" + (env["PATH"] ?: "")
            val started = System.currentTimeMillis()
            try {
                val p = pb.start()
                proc = p
                running = true
                pid = pidOf(p)
                updateNote("运行中")
                val code = p.waitFor()
                running = false
                pid = 0
                if (!wanted) break
                updateNote("已退出 ($code)，${backoff}s 后重启")
            } catch (e: Exception) {
                running = false
                updateNote("启动失败: ${e.message}")
            }
            if (System.currentTimeMillis() - started > 120_000) backoff = 2
            try { Thread.sleep(backoff * 1000) } catch (_: InterruptedException) { break }
            backoff = (backoff * 2).coerceAtMost(60)
        }
    }

    private fun pidOf(p: Process): Int = try {
        val f = p.javaClass.getDeclaredField("pid"); f.isAccessible = true; f.getInt(p)
    } catch (_: Exception) { 0 }

    override fun onDestroy() {
        wanted = false
        val p = proc
        p?.destroy()
        // ShellGate stops cloudflared and exits within a few seconds of SIGTERM; make sure it does
        if (p != null) Thread {
            try { if (Build.VERSION.SDK_INT >= 26 && !p.waitFor(6, java.util.concurrent.TimeUnit.SECONDS)) p.destroyForcibly() } catch (_: Exception) {}
        }.start()
        worker?.interrupt()
        running = false
        releaseLocks()
        super.onDestroy()
    }
}
