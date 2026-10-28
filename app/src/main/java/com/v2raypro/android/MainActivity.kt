package com.v2raypro.android

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.content.BroadcastReceiver
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.TrafficStats
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.webkit.JavascriptInterface
import android.webkit.JsPromptResult
import android.webkit.WebChromeClient
import android.webkit.WebView
import android.webkit.WebViewClient
import com.v2raypro.android.core.StorageRepository
import com.v2raypro.android.core.SubscriptionManager
import com.v2raypro.android.core.UriParser
import com.v2raypro.android.network.NetworkDiagnosticsEngine
import com.v2raypro.android.service.V2RayVpnService
import com.v2raypro.android.service.XrayCoreRunner
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * MainActivity hosting assets/index.html.
 *
 * Bridges JavaScript to Native Android & Kotlin engines through two synchronized channels:
 *   1. window.AndroidBridge.call(cmd, payload)   (@JavascriptInterface)
 *   2. window.prompt(cmd, payload)               (WebChromeClient.onJsPrompt)
 *
 * Supported commands:
 *   - v2ray://connect      -> Validates config, calls VpnService.prepare(), starts V2RayVpnService
 *   - v2ray://disconnect   -> Stops V2RayVpnService and closes TUN fd
 *   - v2ray://notify       -> Updates ongoing foreground notification with real traffic stats
 *   - v2ray://clipboard    -> Reads primary clip text from Android ClipboardManager
 *   - v2ray://traffic      -> Reads real OS TrafficStats Rx/Tx byte counters
 *   - v2ray://ping         -> Runs real async TCP socket ping on background IO pool
 *   - v2ray://sync_sub     -> Fetches HTTPS subscription natively without CORS proxies
 *   - v2ray://status       -> Queries real V2RayVpnService.isRunning & native Xray core availability
 */
class MainActivity : Activity() {
    private lateinit var webView: WebView
    private var pendingPayload: String = ""
    private val main = Handler(Looper.getMainLooper())
    private val ioScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val repo by lazy { StorageRepository(applicationContext) }
    private val subManager by lazy { SubscriptionManager(repo) }
    private val diagnostics by lazy { NetworkDiagnosticsEngine() }
    private val coreRunner by lazy { XrayCoreRunner(applicationContext) }

    private var lastRxBytes: Long = -1L
    private var lastTxBytes: Long = -1L
    private var lastTrafficTs: Long = 0L

    private val stateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val running = intent?.getBooleanExtra("running", false) ?: false
            val err = intent?.getStringExtra("error")
            if (!running && !err.isNullOrBlank()) {
                js("window.__onVpnError && window.__onVpnError(${JSONObject.quote(err)})")
            } else {
                js("window.__onVpnState && window.__onVpnState($running)")
            }
        }
    }

    inner class Bridge {
        @JavascriptInterface
        fun call(cmd: String?, payload: String?): String = runOnMainBlocking {
            handleCommand(cmd ?: "", payload ?: "")
        }
    }

    @SuppressLint("SetJavaScriptEnabled", "AddJavascriptInterface")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        webView = WebView(this)
        webView.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            allowFileAccess = true
            setSupportZoom(false)
        }
        webView.isFocusable = true
        webView.isFocusableInTouchMode = true
        webView.addJavascriptInterface(Bridge(), "AndroidBridge")
        webView.webViewClient = object : WebViewClient() {
            override fun onPageFinished(view: WebView?, url: String?) {
                syncNativeStatusToWebView()
                handleIncomingDeepLink(intent)
            }
        }
        webView.webChromeClient = object : WebChromeClient() {
            override fun onJsPrompt(
                view: WebView?, url: String?, message: String?, defaultValue: String?, result: JsPromptResult?
            ): Boolean {
                val cmd = message ?: return false
                if (!cmd.startsWith("v2ray://")) return false
                result?.confirm(handleCommand(cmd, defaultValue ?: ""))
                return true
            }
        }
        setContentView(webView)
        webView.loadUrl("file:///android_asset/index.html")
        webView.requestFocus()

        requestNotificationPermissionOnceOnFirstLaunch()
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIncomingDeepLink(intent)
    }

    private fun handleIncomingDeepLink(intent: Intent?) {
        val dataUri = intent?.dataString?.trim().orEmpty()
        if (dataUri.isNotEmpty() && (
                dataUri.startsWith("vless://", true) ||
                dataUri.startsWith("vmess://", true) ||
                dataUri.startsWith("trojan://", true) ||
                dataUri.startsWith("ss://", true)
            )
        ) {
            intent?.data = null
            js("window.importUserConfigs && window.importUserConfigs(${JSONObject.quote(dataUri)})")
        }
    }

    private fun requestNotificationPermissionOnceOnFirstLaunch() {
        if (Build.VERSION.SDK_INT < 33) return
        if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) return
        val prefs = getSharedPreferences("v2ray_pro_prefs", Context.MODE_PRIVATE)
        if (!prefs.getBoolean("notif_perm_requested", false)) {
            prefs.edit().putBoolean("notif_perm_requested", true).apply()
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIF)
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQ_NOTIF) {
            val granted = grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED
            js("window.__onNotifPermissionResult && window.__onNotifPermissionResult($granted)")
        }
    }

    override fun onStart() {
        super.onStart()
        val f = IntentFilter(V2RayVpnService.ACTION_STATE)
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(stateReceiver, f, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            registerReceiver(stateReceiver, f)
        }
    }

    override fun onResume() {
        super.onResume()
        if (::webView.isInitialized) {
            syncNativeStatusToWebView()
        }
    }

    override fun onStop() {
        runCatching { unregisterReceiver(stateReceiver) }
        super.onStop()
    }

    override fun onDestroy() {
        ioScope.cancel()
        super.onDestroy()
    }

    private fun syncNativeStatusToWebView() {
        val vpnConsentGranted = VpnService.prepare(this) == null
        val notifGranted = if (Build.VERSION.SDK_INT >= 33) {
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
        } else true
        val coreBundled = coreRunner.isNativeCoreAvailable()
        val coreVer = coreRunner.getCoreVersion()
        val serviceRunning = V2RayVpnService.isRunning && vpnConsentGranted

        val statusJson = JSONObject().apply {
            put("isAndroidApk", true)
            put("serviceRunning", serviceRunning)
            put("vpnConsentGranted", vpnConsentGranted)
            put("notifGranted", notifGranted)
            put("coreBundled", coreBundled)
            put("coreVersion", coreVer)
        }
        js("window.__onNativeStatusSync && window.__onNativeStatusSync($statusJson)")
    }

    private fun <T> runOnMainBlocking(block: () -> T): T where T : Any {
        if (Looper.myLooper() == Looper.getMainLooper()) return block()
        var out: Any? = null
        val latch = CountDownLatch(1)
        main.post {
            try {
                out = block()
            } catch (t: Throwable) {
                Log.e(TAG, "bridge error", t)
            } finally {
                latch.countDown()
            }
        }
        latch.await(5, TimeUnit.SECONDS)
        @Suppress("UNCHECKED_CAST")
        return (out ?: "") as T
    }

    private fun handleCommand(cmd: String, payload: String): String {
        return when (cmd) {
            "v2ray://connect" -> {
                val prep = VpnService.prepare(this)
                if (prep != null) {
                    pendingPayload = payload
                    startActivityForResult(prep, REQ_VPN)
                    "PROMPTING"
                } else {
                    startVpn(payload)
                    "STARTING"
                }
            }
            "v2ray://disconnect" -> {
                startService(Intent(this, V2RayVpnService::class.java).setAction(V2RayVpnService.ACTION_STOP))
                "DISCONNECTED"
            }
            "v2ray://notify" -> {
                if (V2RayVpnService.isRunning) {
                    startService(
                        Intent(this, V2RayVpnService::class.java)
                            .setAction(V2RayVpnService.ACTION_NOTIFY)
                            .putExtra(V2RayVpnService.EXTRA_NOTIF, payload)
                    )
                }
                "OK"
            }
            "v2ray://clipboard" -> {
                val cm = getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                val clip = cm?.primaryClip
                if (clip != null && clip.itemCount > 0) {
                    clip.getItemAt(0)?.coerceToText(this)?.toString() ?: ""
                } else {
                    ""
                }
            }
            "v2ray://traffic" -> {
                readRealTrafficStatsJson()
            }
            "v2ray://ping" -> {
                runAsyncTcpPing(payload)
                "ASYNC"
            }
            "v2ray://sync_sub" -> {
                runAsyncSubSync(payload)
                "ASYNC"
            }
            "v2ray://status" -> {
                syncNativeStatusToWebView()
                "OK"
            }
            else -> ""
        }
    }

    private fun readRealTrafficStatsJson(): String {
        val rx = TrafficStats.getTotalRxBytes().takeIf { it >= 0 } ?: 0L
        val tx = TrafficStats.getTotalTxBytes().takeIf { it >= 0 } ?: 0L
        val now = System.currentTimeMillis()
        var dlBps = 0L
        var ulBps = 0L
        if (lastRxBytes >= 0 && lastTxBytes >= 0 && now > lastTrafficTs) {
            val dtMs = (now - lastTrafficTs).coerceAtLeast(1L)
            dlBps = ((rx - lastRxBytes).coerceAtLeast(0L) * 1000L) / dtMs
            ulBps = ((tx - lastTxBytes).coerceAtLeast(0L) * 1000L) / dtMs
        }
        lastRxBytes = rx
        lastTxBytes = tx
        lastTrafficTs = now
        return JSONObject().apply {
            put("dlBps", dlBps)
            put("ulBps", ulBps)
            put("rxBytes", rx)
            put("txBytes", tx)
        }.toString()
    }

    private fun runAsyncTcpPing(payload: String) {
        ioScope.launch {
            try {
                val req = JSONObject(payload)
                val uid = req.optString("uid", "")
                val host = req.optString("address", "")
                val port = req.optInt("port", 443)
                val name = req.optString("remark", host)
                val dummy = com.v2raypro.android.model.ServerProfile(
                    id = uid,
                    name = name,
                    protocol = "vless",
                    address = host,
                    port = port,
                    uuidOrPassword = "ping"
                )
                val res = diagnostics.pingServerTcp(dummy, timeoutMs = 2500)
                val respJson = JSONObject().apply {
                    put("uid", uid)
                    put("status", res.status)
                    if (res.latencyMs != null) put("latencyMs", res.latencyMs) else put("latencyMs", JSONObject.NULL)
                    put("errorDetail", res.errorDetail ?: "")
                }
                js("window.__onNativePingResult && window.__onNativePingResult($respJson)")
            } catch (e: Exception) {
                Log.w(TAG, "ping error: ${e.message}")
            }
        }
    }

    private fun runAsyncSubSync(payload: String) {
        ioScope.launch {
            try {
                val req = JSONObject(payload)
                val url = req.optString("url", "")
                val prefix = req.optString("prefix", "")
                val res = subManager.syncSubscriptionUrl(url, prefix)
                val state = repo.loadState()
                val profilesArr = JSONArray()
                state.profiles.filter { it.subscriptionId == res.subscriptionId }.forEach { p ->
                    profilesArr.put(JSONObject().apply {
                        put("uid", p.id)
                        put("protocol", p.protocol.uppercase())
                        put("address", p.address)
                        put("port", p.port)
                        put("id", p.uuidOrPassword)
                        put("remark", p.name)
                        put("net", p.network)
                        put("tls", p.security)
                        put("sni", p.sni)
                        put("path", p.path)
                        put("rawUri", p.rawUri)
                    })
                }
                val respJson = JSONObject().apply {
                    put("url", res.url)
                    put("success", res.success)
                    put("httpStatus", res.httpStatus)
                    put("addedCount", res.addedCount)
                    put("updatedCount", res.updatedCount)
                    put("removedCount", res.removedCount)
                    put("totalActive", res.totalActive)
                    put("errorReason", res.errorReason ?: "")
                    put("profiles", profilesArr)
                }
                js("window.__onNativeSubSyncResult && window.__onNativeSubSyncResult($respJson)")
            } catch (e: Exception) {
                Log.w(TAG, "sub sync error: ${e.message}")
            }
        }
    }

    private fun startVpn(payload: String) {
        var uri = ""
        var notif = "V2Ray Pro"
        var routingMode = "bypass_lan"
        var domainStrategy = "IPIfNonMatch"
        var killSwitch = true
        var ipv6Sinkhole = true
        var webrtcBlock = true
        var remoteDns = true

        runCatching {
            val o = JSONObject(payload)
            uri = o.optString("uri", "")
            notif = o.optString("notif", notif)
            routingMode = o.optString("routingMode", routingMode)
            domainStrategy = o.optString("domainStrategy", domainStrategy)
            if (o.has("killSwitch")) killSwitch = o.optBoolean("killSwitch", true)
            if (o.has("ipv6Sinkhole")) ipv6Sinkhole = o.optBoolean("ipv6Sinkhole", true)
            if (o.has("webrtcBlock")) webrtcBlock = o.optBoolean("webrtcBlock", true)
            if (o.has("remoteDns")) remoteDns = o.optBoolean("remoteDns", true)
        }

        // Persist active routing/anti-leak settings & profile to StorageRepository
        runCatching {
            val current = repo.loadState()
            val updatedAntiLeak = current.antiLeakConfig.copy(
                strictKillSwitch = killSwitch,
                blockIpv6Leak = ipv6Sinkhole,
                blockWebRtcStunLeak = webrtcBlock,
                enforceRemoteDoH = remoteDns,
                routingMode = routingMode,
                domainStrategy = domainStrategy
            )
            val parsedProfile = if (uri.isNotBlank()) UriParser.parseSingleUri(uri).getOrNull() else null
            val updatedProfiles = if (parsedProfile != null) {
                val existing = current.profiles.firstOrNull { it.stableEndpointKey() == parsedProfile.stableEndpointKey() }
                if (existing != null) current.profiles else (current.profiles + parsedProfile)
            } else current.profiles
            val selId = if (parsedProfile != null) {
                updatedProfiles.firstOrNull { it.stableEndpointKey() == parsedProfile.stableEndpointKey() }?.id
            } else current.selectedProfileId

            repo.saveState(
                current.copy(
                    profiles = updatedProfiles,
                    selectedProfileId = selId,
                    antiLeakConfig = updatedAntiLeak
                )
            )
        }

        val i = Intent(this, V2RayVpnService::class.java)
            .setAction(V2RayVpnService.ACTION_START)
            .putExtra(V2RayVpnService.EXTRA_URI, uri)
            .putExtra(V2RayVpnService.EXTRA_NOTIF, notif)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) startForegroundService(i) else startService(i)
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_VPN) {
            val granted = resultCode == RESULT_OK
            if (granted) {
                startVpn(pendingPayload)
            }
            js("window.__onVpnPermissionResult && window.__onVpnPermissionResult($granted)")
        }
    }

    private fun js(code: String) = webView.post { webView.evaluateJavascript(code, null) }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        if (webView.canGoBack()) webView.goBack() else super.onBackPressed()
    }

    companion object {
        private const val TAG = "V2RayPro"
        private const val REQ_VPN = 1001
        private const val REQ_NOTIF = 2002
    }
}
