package io.shellgate.app

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.GestureDescription
import android.graphics.Bitmap
import android.graphics.Path
import android.graphics.Rect
import android.os.Build
import android.os.Bundle
import android.util.Base64
import android.view.Display
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.InetAddress
import java.net.ServerSocket
import java.security.SecureRandom
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit

/**
 * Accessibility bridge for the ShellGate binary (which runs as a child process of this app and
 * cannot use Android APIs itself). While the user has the service turned on, it listens on
 * 127.0.0.1 at a random port and writes {port, secret} to files/logs/a11y.json (private to the
 * app's uid, which the binary shares). One JSON request per connection, one JSON line back.
 *
 * ops: ping, tree, click, set_text, tap, swipe, global, screenshot (Android 11+).
 */
class SgA11yService : AccessibilityService() {

    companion object {
        @Volatile var active = false
            private set
    }

    private var server: ServerSocket? = null
    private var thread: Thread? = null
    private val refs = ArrayList<AccessibilityNodeInfo>()
    private lateinit var secret: String

    override fun onServiceConnected() {
        super.onServiceConnected()
        val b = ByteArray(24); SecureRandom().nextBytes(b)
        secret = b.joinToString("") { "%02x".format(it) }
        val s = ServerSocket(0, 8, InetAddress.getByName("127.0.0.1"))
        server = s
        val f = File(SgService.stateDir(this).apply { mkdirs() }, "a11y.json")
        val tmp = File(f.path + ".tmp")
        tmp.writeText(JSONObject().put("port", s.localPort).put("secret", secret).put("api", Build.VERSION.SDK_INT).toString())
        tmp.setReadable(false, false); tmp.setReadable(true, true)
        tmp.renameTo(f)
        active = true
        thread = Thread({ serve(s) }, "sg-a11y").also { it.isDaemon = true; it.start() }
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {}
    override fun onInterrupt() {}

    override fun onDestroy() {
        active = false
        try { server?.close() } catch (_: Exception) {}
        File(SgService.stateDir(this), "a11y.json").delete()
        super.onDestroy()
    }

    private fun serve(s: ServerSocket) {
        while (!s.isClosed) {
            val c = try { s.accept() } catch (_: Exception) { break }
            Thread {
                c.use { sock ->
                    sock.soTimeout = 30_000
                    val out = try {
                        val line = sock.getInputStream().bufferedReader().readLine() ?: ""
                        val req = JSONObject(line)
                        if (req.optString("secret") != secret) JSONObject().put("err", "unauthorized")
                        else try { JSONObject().put("ok", handle(req)) } catch (e: Exception) { JSONObject().put("err", e.message ?: e.toString()) }
                    } catch (e: Exception) { JSONObject().put("err", "bad request: ${e.message}") }
                    sock.getOutputStream().write((out.toString() + "\n").toByteArray())
                    sock.getOutputStream().flush()
                }
            }.start()
        }
    }

    private fun handle(r: JSONObject): Any = when (r.optString("op")) {
        "ping" -> JSONObject().put("api", Build.VERSION.SDK_INT).put("screenshot", Build.VERSION.SDK_INT >= 30)
        "tree" -> tree(r.optInt("max_nodes", 300).coerceIn(10, 2000))
        "click" -> nodeAction(r.getInt("ref"), AccessibilityNodeInfo.ACTION_CLICK, null)
        "long_click" -> nodeAction(r.getInt("ref"), AccessibilityNodeInfo.ACTION_LONG_CLICK, null)
        "scroll_forward" -> nodeAction(r.getInt("ref"), AccessibilityNodeInfo.ACTION_SCROLL_FORWARD, null)
        "scroll_backward" -> nodeAction(r.getInt("ref"), AccessibilityNodeInfo.ACTION_SCROLL_BACKWARD, null)
        "set_text" -> nodeAction(r.getInt("ref"), AccessibilityNodeInfo.ACTION_SET_TEXT, Bundle().apply {
            putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, r.optString("text"))
        })
        "tap" -> gesture(r.getDouble("x").toFloat(), r.getDouble("y").toFloat(), null, null, r.optLong("ms", 60))
        "swipe" -> gesture(r.getDouble("x").toFloat(), r.getDouble("y").toFloat(), r.getDouble("x2").toFloat(), r.getDouble("y2").toFloat(), r.optLong("ms", 300))
        "global" -> {
            val a = when (r.optString("action")) {
                "back" -> GLOBAL_ACTION_BACK
                "home" -> GLOBAL_ACTION_HOME
                "recents" -> GLOBAL_ACTION_RECENTS
                "notifications" -> GLOBAL_ACTION_NOTIFICATIONS
                "quick_settings" -> GLOBAL_ACTION_QUICK_SETTINGS
                "power_dialog" -> GLOBAL_ACTION_POWER_DIALOG
                "lock_screen" -> if (Build.VERSION.SDK_INT >= 28) GLOBAL_ACTION_LOCK_SCREEN else throw IllegalArgumentException("lock_screen needs Android 9")
                else -> throw IllegalArgumentException("unknown global action")
            }
            JSONObject().put("done", performGlobalAction(a))
        }
        "screenshot" -> screenshot(r.optInt("max_width", 1080))
        else -> throw IllegalArgumentException("unknown op")
    }

    private fun tree(max: Int): JSONObject {
        synchronized(refs) {
            refs.clear()
            val lines = StringBuilder()
            val roots = windows.mapNotNull { it.root }.ifEmpty { listOfNotNull(rootInActiveWindow) }
            for (root in roots) walk(root, 0, lines, max)
            return JSONObject().put("tree", lines.toString()).put("count", refs.size).put("truncated", refs.size >= max)
                .put("package", rootInActiveWindow?.packageName?.toString() ?: "")
        }
    }

    private fun walk(n: AccessibilityNodeInfo, depth: Int, out: StringBuilder, max: Int) {
        if (refs.size >= max) return
        val text = (n.text ?: n.contentDescription ?: "").toString().replace("\n", " ").take(80)
        val id = n.viewIdResourceName?.substringAfter(":id/") ?: ""
        val interesting = text.isNotEmpty() || n.isClickable || n.isEditable || n.isScrollable || n.isCheckable
        var d = depth
        if (interesting) {
            refs.add(n)
            val r = Rect(); n.getBoundsInScreen(r)
            val cls = n.className?.toString()?.substringAfterLast('.') ?: "View"
            val flags = buildString {
                if (n.isClickable) append(" click")
                if (n.isEditable) append(" edit")
                if (n.isScrollable) append(" scroll")
                if (n.isCheckable) append(if (n.isChecked) " checked" else " unchecked")
                if (!n.isEnabled) append(" disabled")
                if (n.isPassword) append(" password")
            }
            val shown = if (n.isPassword) "" else text
            out.append("  ".repeat(depth.coerceAtMost(12))).append('[').append(refs.size).append("] ").append(cls)
            if (shown.isNotEmpty()) out.append(" \"").append(shown).append('"')
            if (id.isNotEmpty()) out.append(" #").append(id)
            out.append(" @(").append(r.left).append(',').append(r.top).append(' ').append(r.width()).append('x').append(r.height()).append(')')
            out.append(flags).append('\n')
            d = depth + 1
        }
        for (i in 0 until n.childCount) {
            val c = n.getChild(i) ?: continue
            walk(c, d, out, max)
        }
    }

    private fun nodeAction(ref: Int, action: Int, args: Bundle?): JSONObject {
        val n = synchronized(refs) { refs.getOrNull(ref - 1) } ?: throw IllegalArgumentException("ref $ref not in the last tree; call tree again")
        val ok = if (args != null) n.performAction(action, args) else n.performAction(action)
        if (!ok && action == AccessibilityNodeInfo.ACTION_CLICK) {
            // not clickable itself: tap its centre
            val r = Rect(); n.getBoundsInScreen(r)
            return gesture(r.exactCenterX(), r.exactCenterY(), null, null, 60).put("fallback", "tap")
        }
        return JSONObject().put("done", ok)
    }

    private fun gesture(x: Float, y: Float, x2: Float?, y2: Float?, ms: Long): JSONObject {
        val p = Path().apply { moveTo(x, y); if (x2 != null && y2 != null) lineTo(x2, y2) }
        val g = GestureDescription.Builder().addStroke(GestureDescription.StrokeDescription(p, 0, ms.coerceIn(1, 5000))).build()
        val latch = CountDownLatch(1)
        var done = false
        dispatchGesture(g, object : GestureResultCallback() {
            override fun onCompleted(d: GestureDescription?) { done = true; latch.countDown() }
            override fun onCancelled(d: GestureDescription?) { latch.countDown() }
        }, null)
        latch.await(ms + 3000, TimeUnit.MILLISECONDS)
        return JSONObject().put("done", done)
    }

    private fun screenshot(maxW: Int): JSONObject {
        if (Build.VERSION.SDK_INT < 30) throw IllegalStateException("screenshots need Android 11 or newer")
        val latch = CountDownLatch(1)
        var result: JSONObject? = null
        var error: String? = null
        val exec = Executor { it.run() }
        takeScreenshot(Display.DEFAULT_DISPLAY, exec, object : TakeScreenshotCallback {
            override fun onSuccess(s: ScreenshotResult) {
                try {
                    val hw = Bitmap.wrapHardwareBuffer(s.hardwareBuffer, s.colorSpace)
                    s.hardwareBuffer.close()
                    if (hw == null) { error = "could not read the screenshot"; return }
                    val soft = hw.copy(Bitmap.Config.ARGB_8888, false)
                    val w = soft.width; val h = soft.height
                    val scaled = if (maxW in 1 until w) Bitmap.createScaledBitmap(soft, maxW, (h.toLong() * maxW / w).toInt(), true) else soft
                    val bos = ByteArrayOutputStream()
                    scaled.compress(Bitmap.CompressFormat.PNG, 100, bos)
                    result = JSONObject().put("width", scaled.width).put("height", scaled.height)
                        .put("screen_width", w).put("screen_height", h)
                        .put("png", Base64.encodeToString(bos.toByteArray(), Base64.NO_WRAP))
                } catch (e: Exception) { error = e.message } finally { latch.countDown() }
            }
            override fun onFailure(code: Int) { error = "takeScreenshot failed ($code)"; latch.countDown() }
        })
        latch.await(10, TimeUnit.SECONDS)
        return result ?: throw IllegalStateException(error ?: "screenshot timed out")
    }
}
