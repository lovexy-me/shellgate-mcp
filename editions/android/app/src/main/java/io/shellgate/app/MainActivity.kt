package io.shellgate.app

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import android.provider.Settings
import android.webkit.JavascriptInterface
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import java.io.File

/**
 * Shows the binary's own admin page (http://127.0.0.1:<admin_port>/) in a WebView, with the
 * admin key read from the app's private state dir. The page gets a small `SGApp` bridge for the
 * things only the app can do: start/stop the service, autostart, battery-optimisation exemption.
 */
class MainActivity : Activity() {

    private lateinit var web: WebView
    private val ui = Handler(Looper.getMainLooper())
    private var tries = 0

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        web = WebView(this)
        setContentView(web)
        web.settings.javaScriptEnabled = true
        web.settings.domStorageEnabled = true
        web.addJavascriptInterface(Bridge(), "SGApp")
        web.webViewClient = object : WebViewClient() {
            // stay on the local admin page; open anything else in the browser
            override fun shouldOverrideUrlLoading(v: WebView, r: WebResourceRequest): Boolean {
                val u = r.url
                if (u.host == "127.0.0.1") return false
                startActivity(Intent(Intent.ACTION_VIEW, u))
                return true
            }
        }
        if (Build.VERSION.SDK_INT >= 33) {
            requestPermissions(arrayOf("android.permission.POST_NOTIFICATIONS"), 1)
        }
        if (Prefs.wantRunning(this)) SgService.start(this)
        showLoading("正在启动 ShellGate…")
        ui.postDelayed({ openAdmin() }, 800)
    }

    private fun adminPort(): Int {
        val cfg = SgService.configFile(this)
        val line = try { cfg.readLines() } catch (_: Exception) { emptyList() }
            .map { it.trim() }
            .lastOrNull { !it.startsWith("#") && (it.startsWith("admin_port=") || it.startsWith("SHELLGATE_ADMIN_PORT=")) }
        return line?.substringAfter('=')?.trim()?.toIntOrNull() ?: 8791
    }

    private fun openAdmin() {
        val keyFile = File(SgService.stateDir(this), "admin.key")
        val key = try { keyFile.readText().trim() } catch (_: Exception) { "" }
        if (key.length < 32) {
            if (++tries > 40) {
                val log = try { File(SgService.stateDir(this), "shellgate.log").readLines().takeLast(20).joinToString("\n") } catch (_: Exception) { "" }
                showLoading("ShellGate 没有启动起来。\n\n$log")
                return
            }
            ui.postDelayed({ openAdmin() }, 500)
            return
        }
        web.loadUrl("http://127.0.0.1:${adminPort()}/#k=$key")
    }

    private fun showLoading(msg: String) {
        val esc = msg.replace("&", "&amp;").replace("<", "&lt;")
        web.loadDataWithBaseURL(null,
            "<html><body style='font-family:sans-serif;padding:24px;white-space:pre-wrap'>$esc</body></html>",
            "text/html", "utf-8", null)
    }

    override fun onResume() {
        super.onResume()
        web.evaluateJavascript("window.load && load()", null)
    }

    inner class Bridge {
        @JavascriptInterface fun running(): Boolean = SgService.running
        @JavascriptInterface fun start() { Prefs.setWantRunning(this@MainActivity, true); SgService.start(this@MainActivity); tries = 0; ui.postDelayed({ openAdmin() }, 1500) }
        @JavascriptInterface fun stop() { Prefs.setWantRunning(this@MainActivity, false); SgService.stop(this@MainActivity) }
        @JavascriptInterface fun autostart(): Boolean = Prefs.autostart(this@MainActivity)
        @JavascriptInterface fun setAutostart(on: Boolean) = Prefs.setAutostart(this@MainActivity, on)
        @JavascriptInterface fun batteryExempt(): Boolean =
            getSystemService(PowerManager::class.java).isIgnoringBatteryOptimizations(packageName)
        @SuppressLint("BatteryLife")
        @JavascriptInterface fun requestBatteryExempt() {
            ui.post {
                try {
                    startActivity(Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:$packageName")))
                } catch (_: Exception) {
                    startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
                }
            }
        }
        @JavascriptInterface fun a11yEnabled(): Boolean = SgA11yService.active
        @JavascriptInterface fun openA11ySettings() {
            ui.post { startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)) }
        }
        @JavascriptInterface fun allFilesGranted(): Boolean =
            if (Build.VERSION.SDK_INT >= 30) android.os.Environment.isExternalStorageManager()
            else checkSelfPermission("android.permission.WRITE_EXTERNAL_STORAGE") == android.content.pm.PackageManager.PERMISSION_GRANTED
        @JavascriptInterface fun requestAllFiles() {
            ui.post {
                if (Build.VERSION.SDK_INT >= 30) {
                    try {
                        startActivity(Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.parse("package:$packageName")))
                    } catch (_: Exception) {
                        startActivity(Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION))
                    }
                } else {
                    requestPermissions(arrayOf("android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE"), 2)
                }
            }
        }
        @JavascriptInterface fun appVersion(): String = packageManager.getPackageInfo(packageName, 0).versionName ?: ""
    }
}
