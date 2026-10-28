package com.v2raypro.android.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.IpPrefix
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import com.v2raypro.android.MainActivity
import com.v2raypro.android.core.StorageRepository
import com.v2raypro.android.core.UriParser
import com.v2raypro.android.core.XrayConfigBuilder
import com.v2raypro.android.model.AntiLeakAndStaticIpConfig
import com.v2raypro.android.model.ServerProfile
import java.io.File
import java.net.Inet4Address
import java.net.InetAddress
import java.net.NetworkInterface
import java.util.Collections

/**
 * V2Ray Pro Android VpnService.
 *
 * Key guarantees:
 * 1. Verifies native Xray core availability before claiming connection success.
 * 2. Preserves local LAN / Wi-Fi gateway access when routingMode != "all_tunnel" by excluding
 *    RFC1918 private subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, multicast)
 *    from the TUN routing table while keeping explicit /32 routes for TUN DNS & gateway.
 * 3. Detects local Wi-Fi subnet conflicts with 10.200.200.0/30 and switches to 172.31.250.2/30 if needed.
 * 4. Safely manages ParcelFileDescriptor dup/close so failed starts never leak file descriptors.
 * 5. Monitors network changes (Wi-Fi <-> Mobile Data) via ConnectivityManager.NetworkCallback.
 */
class V2RayVpnService : VpnService() {

    private var tunInterface: ParcelFileDescriptor? = null
    private val core by lazy { XrayCoreRunner(applicationContext) }
    @Volatile private var worker: Thread? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action ?: ACTION_START

        when (action) {
            ACTION_STOP -> {
                stopVpnTunnel()
                return START_NOT_STICKY
            }
            ACTION_NOTIFY -> {
                if (isRunning) {
                    updateNotification(intent?.getStringExtra(EXTRA_NOTIF) ?: "")
                }
                return START_STICKY
            }
        }

        // Must enter foreground immediately on Android 8+
        try {
            showForeground(intent?.getStringExtra(EXTRA_NOTIF) ?: "Initializing VPN tunnel...")
        } catch (t: Throwable) {
            Log.e(TAG, "startForeground failed", t)
            fail("Foreground notification error: ${t.message}")
            return START_NOT_STICKY
        }

        val uri = intent?.getStringExtra(EXTRA_URI).orEmpty()
        val repo = StorageRepository(applicationContext)
        val state = repo.loadState()

        val profile: ServerProfile? =
            if (uri.isNotBlank()) UriParser.parseSingleUri(uri).getOrNull()
            else state.profiles.firstOrNull { it.id == state.selectedProfileId } ?: state.profiles.firstOrNull()

        if (profile == null) {
            fail("No valid server profile selected. Import a VLESS/VMess/Trojan/SS config first.")
            return START_NOT_STICKY
        }
        if (profile.protocol.lowercase() !in UriParser.SUPPORTED_PROTOCOLS) {
            fail("Protocol '${profile.protocol}' is not supported by Xray-core (use VLESS, VMess, Trojan, or Shadowsocks).")
            return START_NOT_STICKY
        }

        // Stop previous tunnel instance cleanly before starting new worker
        stopEngineOnly()
        worker = Thread {
            try {
                startVpnTunnel(profile, state.antiLeakConfig, state.routingRules)
            } catch (t: Throwable) {
                Log.e(TAG, "VPN start failed for ${profile.redactedSummary()}", t)
                fail(t.message ?: t.javaClass.simpleName)
            }
        }.also { it.start() }

        return START_STICKY
    }

    private fun startVpnTunnel(
        profile: ServerProfile,
        antiLeak: AntiLeakAndStaticIpConfig,
        rules: List<com.v2raypro.android.model.RoutingRuleItem>
    ) {
        // 0. Fail fast if libv2ray.aar is not bundled so we never create a blackhole TUN interface
        if (!core.isNativeCoreAvailable()) {
            throw IllegalStateException(
                "Xray native core (libv2ray.aar) is not bundled in this APK. Build with app/libs/libv2ray.aar via Gradle."
            )
        }

        // 1. Resolve server hostname BEFORE establishing TUN to avoid DNS-over-tunnel deadlock
        val serverIp = try {
            InetAddress.getAllByName(profile.address)
                .firstOrNull { it is Inet4Address }?.hostAddress
                ?: InetAddress.getByName(profile.address).hostAddress
        } catch (e: Exception) {
            throw IllegalStateException("Cannot resolve server hostname '${profile.address}': ${e.message ?: "DNS failed"}")
        }

        val builder = Builder()
            .setSession("V2Ray Pro — ${profile.name}")
            .setMtu(1500)

        // 2. Choose non-conflicting TUN IPv4 address (avoid collision if local Wi-Fi uses 10.200.200.x)
        val requestedTunIp = if (antiLeak.enforceStaticTunIp) antiLeak.staticTunIpv4 else "10.200.200.2"
        val (tunIp, tunPrefix) = selectSafeTunAddress(requestedTunIp, antiLeak.staticTunPrefixLength)
        builder.addAddress(tunIp, tunPrefix)

        // 3. Configure Routing Policy (Preserve Local LAN vs Full Tunnel)
        val bypassLan = antiLeak.routingMode != "all_tunnel"
        configureBuilderRoutes(builder, bypassLan)

        if (antiLeak.blockIpv6Leak) {
            builder.addAddress("fd00:200:200::2", 126)
            if (bypassLan && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                builder.addRoute("::", 0)
                // Exclude link-local fe80::/10 so IPv6 Neighbor Discovery on LAN stays intact
                builder.excludeRoute(IpPrefix(InetAddress.getByName("fe80::"), 10))
            } else {
                builder.addRoute("2000::", 3) // Route global unicast IPv6 into TUN sinkhole
            }
        }

        builder.addDnsServer("1.1.1.1")
        builder.addDnsServer("1.0.0.1")

        // Exclude our own app package so Xray's outbound sockets go directly through the physical network
        builder.addDisallowedApplication(packageName)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        val pfd = builder.establish()
            ?: throw IllegalStateException("Android VpnService.Builder.establish() returned null (VPN permission revoked)")
        tunInterface = pfd

        val geoOk = File(filesDir, "geosite.dat").exists() && File(filesDir, "geoip.dat").exists()
        val json = XrayConfigBuilder.buildConfig(
            profile = profile,
            antiLeak = antiLeak,
            routingRules = rules,
            serverIp = serverIp,
            geoAssetsAvailable = geoOk
        )

        val dupPfd = pfd.dup()
        val fd = dupPfd.detachFd()
        try {
            core.start(json, fd)
        } catch (t: Throwable) {
            // Ensure detached fd is closed if core.start fails
            runCatching { ParcelFileDescriptor.adoptFd(fd).close() }
            throw t
        }

        isRunning = true
        activeServerName = profile.name
        registerNetworkMonitor()
        Log.i(TAG, "VPN tunnel established for ${profile.redactedSummary()} (bypassLan=$bypassLan, tun=$tunIp/$tunPrefix)")
        sendBroadcast(
            Intent(ACTION_STATE)
                .setPackage(packageName)
                .putExtra("running", true)
                .putExtra("serverName", profile.name)
        )
    }

    /**
     * Configures IPv4 routes on VpnService.Builder.
     * When bypassLan is true:
     * - On Android 13+ (API 33+): uses addRoute("0.0.0.0", 0) + excludeRoute(...) for RFC1918/link-local/multicast.
     * - On Android 7–12 (API 24–32): uses the exact public IPv4 CIDR compliment list that excludes
     *   0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, and 224.0.0.0/3,
     *   plus explicit /32 routes for DNS (1.1.1.1, 1.0.0.1).
     */
    private fun configureBuilderRoutes(builder: Builder, bypassLan: Boolean) {
        if (!bypassLan) {
            builder.addRoute("0.0.0.0", 0)
            return
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            builder.addRoute("0.0.0.0", 0)
            val excludedSubnets = listOf(
                "10.0.0.0" to 8,
                "127.0.0.0" to 8,
                "169.254.0.0" to 16,
                "172.16.0.0" to 12,
                "192.168.0.0" to 16,
                "224.0.0.0" to 3
            )
            for ((net, prefix) in excludedSubnets) {
                builder.excludeRoute(IpPrefix(InetAddress.getByName(net), prefix))
            }
            // Ensure DNS servers are always routed into TUN even if local network uses 10.x.x.x
            builder.addRoute("1.1.1.1", 32)
            builder.addRoute("1.0.0.1", 32)
        } else {
            // Public IPv4 space excluding 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/3
            for ((net, prefix) in PUBLIC_IPV4_ROUTES_EXCLUDING_LAN) {
                builder.addRoute(net, prefix)
            }
        }
    }

    private fun selectSafeTunAddress(preferredIp: String, preferredPrefix: Int): Pair<String, Int> {
        val localIps = runCatching {
            Collections.list(NetworkInterface.getNetworkInterfaces())
                .filter { it.isUp && !it.isLoopback }
                .flatMap { Collections.list(it.inetAddresses) }
                .filterIsInstance<Inet4Address>()
                .map { it.hostAddress ?: "" }
        }.getOrDefault(emptyList())

        val prefix24 = preferredIp.substringBeforeLast(".", "10.200.200")
        val hasConflict = localIps.any { it.startsWith("$prefix24.") }
        return if (hasConflict) {
            "172.31.250.2" to 30
        } else {
            preferredIp to preferredPrefix.coerceIn(24, 30)
        }
    }

    private fun registerNetworkMonitor() {
        unregisterNetworkMonitor()
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                Log.i(TAG, "Underlying network available: $network")
            }
            override fun onLost(network: Network) {
                Log.w(TAG, "Underlying network lost: $network")
            }
        }
        runCatching {
            val req = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
            cm.registerNetworkCallback(req, cb)
            networkCallback = cb
        }
    }

    private fun unregisterNetworkMonitor() {
        val cb = networkCallback ?: return
        networkCallback = null
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        runCatching { cm.unregisterNetworkCallback(cb) }
    }

    private fun fail(message: String) {
        isRunning = false
        activeServerName = ""
        stopEngineOnly()
        sendBroadcast(
            Intent(ACTION_STATE)
                .setPackage(packageName)
                .putExtra("running", false)
                .putExtra("error", message)
        )
        stopForegroundCompat()
        stopSelf()
    }

    private fun stopEngineOnly() {
        unregisterNetworkMonitor()
        runCatching { core.stop() }
        runCatching { tunInterface?.close() }
        tunInterface = null
    }

    private fun stopVpnTunnel() {
        isRunning = false
        activeServerName = ""
        stopEngineOnly()
        sendBroadcast(
            Intent(ACTION_STATE)
                .setPackage(packageName)
                .putExtra("running", false)
        )
        stopForegroundCompat()
        stopSelf()
    }

    override fun onRevoke() {
        Log.w(TAG, "VPN permission revoked by system/user")
        stopVpnTunnel()
    }

    override fun onDestroy() {
        isRunning = false
        activeServerName = ""
        stopEngineOnly()
        super.onDestroy()
    }

    private fun buildNotification(text: String): Notification {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "V2Ray Pro VPN Status", NotificationManager.IMPORTANCE_LOW)
            )
        }
        val pi = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val b = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return b.setContentTitle("V2Ray Pro • VPN Active")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(pi)
            .build()
    }

    private fun showForeground(text: String) {
        val n = buildNotification(text)
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIF_ID, n)
        }
    }

    private fun updateNotification(text: String) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIF_ID, buildNotification(text))
    }

    @Suppress("DEPRECATION")
    private fun stopForegroundCompat() {
        if (Build.VERSION.SDK_INT >= 24) stopForeground(STOP_FOREGROUND_REMOVE) else stopForeground(true)
    }

    companion object {
        const val ACTION_START = "com.v2raypro.android.START_VPN"
        const val ACTION_STOP = "com.v2raypro.android.STOP_VPN"
        const val ACTION_NOTIFY = "com.v2raypro.android.NOTIFY"
        const val ACTION_STATE = "com.v2raypro.android.VPN_STATE"
        const val EXTRA_URI = "XRAY_URI"
        const val EXTRA_NOTIF = "NOTIF_TEXT"
        @Volatile var isRunning: Boolean = false
        @Volatile var activeServerName: String = ""
        private const val TAG = "V2RayPro"
        private const val CHANNEL_ID = "v2raypro_vpn"
        private const val NOTIF_ID = 1001

        /**
         * Exact public IPv4 CIDR blocks covering 1.0.0.0..223.255.255.255 while omitting:
         * - 0.0.0.0/8
         * - 10.0.0.0/8 (RFC1918)
         * - 127.0.0.0/8 (Loopback)
         * - 169.254.0.0/16 (Link-local)
         * - 172.16.0.0/12 (RFC1918)
         * - 192.168.0.0/16 (RFC1918)
         * - 224.0.0.0/3 (Multicast & Broadcast)
         */
        val PUBLIC_IPV4_ROUTES_EXCLUDING_LAN = listOf(
            "1.0.0.0" to 8,
            "2.0.0.0" to 7,
            "4.0.0.0" to 6,
            "8.0.0.0" to 7,
            "11.0.0.0" to 8,
            "12.0.0.0" to 6,
            "16.0.0.0" to 4,
            "32.0.0.0" to 3,
            "64.0.0.0" to 3,
            "96.0.0.0" to 6,
            "100.0.0.0" to 10,
            "100.128.0.0" to 9,
            "101.0.0.0" to 8,
            "102.0.0.0" to 7,
            "104.0.0.0" to 5,
            "112.0.0.0" to 5,
            "120.0.0.0" to 6,
            "124.0.0.0" to 7,
            "126.0.0.0" to 8,
            "128.0.0.0" to 3,
            "160.0.0.0" to 5,
            "168.0.0.0" to 8,
            "169.0.0.0" to 9,
            "169.128.0.0" to 10,
            "169.192.0.0" to 11,
            "169.224.0.0" to 12,
            "169.240.0.0" to 13,
            "169.248.0.0" to 14,
            "169.252.0.0" to 15,
            "169.255.0.0" to 16,
            "170.0.0.0" to 7,
            "172.0.0.0" to 12,
            "172.32.0.0" to 11,
            "172.64.0.0" to 10,
            "172.128.0.0" to 9,
            "173.0.0.0" to 8,
            "174.0.0.0" to 7,
            "176.0.0.0" to 4,
            "192.0.0.0" to 9,
            "192.128.0.0" to 11,
            "192.160.0.0" to 13,
            "192.169.0.0" to 16,
            "192.170.0.0" to 15,
            "192.172.0.0" to 14,
            "192.176.0.0" to 12,
            "192.192.0.0" to 10,
            "193.0.0.0" to 8,
            "194.0.0.0" to 7,
            "196.0.0.0" to 6,
            "200.0.0.0" to 5,
            "208.0.0.0" to 4
        )
    }
}
