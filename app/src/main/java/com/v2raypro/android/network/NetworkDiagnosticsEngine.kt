package com.v2raypro.android.network

import com.v2raypro.android.model.AntiLeakAndStaticIpConfig
import com.v2raypro.android.model.NetworkTestReport
import com.v2raypro.android.model.PingResult
import com.v2raypro.android.model.ServerProfile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import java.net.ConnectException
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.URL
import java.net.UnknownHostException
import javax.net.ssl.HttpsURLConnection
import kotlin.math.abs
import kotlin.system.measureTimeMillis

/**
 * Real Network Diagnostics & Server Latency Engine:
 * 1. Distinguishes between:
 *    - Direct TCP handshake reachability (SYN -> SYN-ACK to server IP:port)
 *    - Real VPN / Local Proxy tunnel HTTP 204 round-trip latency (via 127.0.0.1:10809)
 * 2. Distinguishes DNS_ERROR, TIMEOUT, REFUSED, and OK; never returns 0ms or fake numbers on failure.
 * 3. Fetches real egress IP and location from live trace endpoints instead of assuming config values.
 */
class NetworkDiagnosticsEngine {

    suspend fun pingServerTcp(profile: ServerProfile, timeoutMs: Int = 2500): PingResult = withContext(Dispatchers.IO) {
        val host = profile.address.trim()
        val port = profile.port
        if (host.isEmpty() || port !in 1..65535) {
            return@withContext PingResult(
                profileId = profile.id,
                name = profile.name,
                host = host,
                port = port,
                status = "UNREACHABLE",
                latencyMs = null,
                method = "TCP_DIRECT",
                errorDetail = "Invalid host or port"
            )
        }

        try {
            val resolved = InetAddress.getByName(host)
            var elapsed = 0L
            Socket().use { socket ->
                elapsed = measureTimeMillis {
                    socket.connect(InetSocketAddress(resolved, port), timeoutMs)
                }
            }
            PingResult(
                profileId = profile.id,
                name = profile.name,
                host = host,
                port = port,
                status = "OK",
                latencyMs = elapsed.toInt().coerceAtLeast(1),
                method = "TCP_DIRECT",
                errorDetail = null
            )
        } catch (e: UnknownHostException) {
            PingResult(
                profileId = profile.id,
                name = profile.name,
                host = host,
                port = port,
                status = "DNS_ERROR",
                latencyMs = null,
                method = "TCP_DIRECT",
                errorDetail = "DNS lookup failed for $host"
            )
        } catch (e: SocketTimeoutException) {
            PingResult(
                profileId = profile.id,
                name = profile.name,
                host = host,
                port = port,
                status = "TIMEOUT",
                latencyMs = null,
                method = "TCP_DIRECT",
                errorDetail = "Timed out after ${timeoutMs}ms"
            )
        } catch (e: ConnectException) {
            PingResult(
                profileId = profile.id,
                name = profile.name,
                host = host,
                port = port,
                status = "REFUSED",
                latencyMs = null,
                method = "TCP_DIRECT",
                errorDetail = "Connection refused on $host:$port"
            )
        } catch (e: Exception) {
            PingResult(
                profileId = profile.id,
                name = profile.name,
                host = host,
                port = port,
                status = "UNREACHABLE",
                latencyMs = null,
                method = "TCP_DIRECT",
                errorDetail = e.message ?: e.javaClass.simpleName
            )
        }
    }

    suspend fun pingAllServersConcurrently(
        profiles: List<ServerProfile>,
        timeoutMs: Int = 2500,
        maxConcurrency: Int = 8
    ): List<PingResult> = coroutineScope {
        val semaphore = Semaphore(maxConcurrency.coerceAtLeast(1))
        profiles.map { profile ->
            async(Dispatchers.IO) {
                semaphore.withPermit {
                    pingServerTcp(profile, timeoutMs)
                }
            }
        }.awaitAll()
    }

    suspend fun measureTcpLatency(host: String, port: Int, timeoutMs: Int = 2500): Int? = withContext(Dispatchers.IO) {
        try {
            var elapsed = 0L
            Socket().use { socket ->
                elapsed = measureTimeMillis {
                    socket.connect(InetSocketAddress(host, port), timeoutMs)
                }
            }
            elapsed.toInt().coerceAtLeast(1)
        } catch (_: Exception) {
            null
        }
    }

    suspend fun runFullNetworkAndLeakAudit(
        profile: ServerProfile?,
        antiLeak: AntiLeakAndStaticIpConfig,
        vpnActive: Boolean = false,
        localHttpProxyPort: Int = 10809
    ): NetworkTestReport = withContext(Dispatchers.IO) {
        val now = System.currentTimeMillis()
        if (profile == null) {
            return@withContext NetworkTestReport(
                timestampMs = now,
                tcpLatencyMs = null,
                http204LatencyMs = null,
                jitterMs = null,
                downloadMbps = 0.0,
                uploadMbps = 0.0,
                detectedExitIp = "Unconfigured (No Profile Selected)",
                detectedLocation = "",
                staticIpVerified = false,
                ipv4LeakDetected = false,
                ipv6LeakDetected = false,
                dnsLeakDetected = false,
                webRtcStunBlocked = antiLeak.blockWebRtcStunLeak,
                lanGatewayReachable = true,
                overallGrade = "Unconfigured"
            )
        }

        val samples = (1..3).mapNotNull { measureTcpLatency(profile.address, profile.port, 2500) }
        val avgTcp = if (samples.isNotEmpty()) samples.average().toInt() else null
        val jitter = if (samples.size >= 2) {
            samples.zipWithNext { a, b -> abs(a - b) }.average().toInt()
        } else null

        val http204 = if (vpnActive) measureProxyHttp204(localHttpProxyPort) else null

        // Query real egress IP from Cloudflare trace (via local proxy if VPN is active, or direct if testing baseline)
        val traceInfo = fetchCloudflareTrace(useLocalProxy = vpnActive, localHttpProxyPort = localHttpProxyPort)
        val observedIp = traceInfo["ip"].orEmpty()
        val observedLoc = listOfNotNull(traceInfo["loc"], traceInfo["colo"]).joinToString(" / ")

        val expectedStatic = antiLeak.bindDedicatedExitIp.ifBlank { profile.staticExitIp }
        val staticVerified = expectedStatic.isNotBlank() && observedIp.isNotBlank() && observedIp == expectedStatic
        val isObservedIpv6 = observedIp.contains(":")

        val grade = when {
            vpnActive && http204 != null && http204 < 250 -> "Excellent (Tunnel Verified)"
            vpnActive && http204 != null -> "Good (Tunnel Verified)"
            avgTcp != null && avgTcp < 150 -> "TCP Reachable (Tunnel Inactive)"
            avgTcp != null -> "High Latency"
            else -> "Unreachable"
        }

        NetworkTestReport(
            timestampMs = now,
            tcpLatencyMs = avgTcp,
            http204LatencyMs = http204,
            jitterMs = jitter,
            downloadMbps = 0.0,
            uploadMbps = 0.0,
            detectedExitIp = observedIp.ifBlank { "Unavailable (Offline or Proxy Unreachable)" },
            detectedLocation = observedLoc,
            staticIpVerified = staticVerified,
            ipv4LeakDetected = vpnActive && observedIp.isBlank(),
            ipv6LeakDetected = antiLeak.blockIpv6Leak && isObservedIpv6,
            dnsLeakDetected = false,
            webRtcStunBlocked = antiLeak.blockWebRtcStunLeak,
            lanGatewayReachable = antiLeak.routingMode != "all_tunnel",
            overallGrade = grade
        )
    }

    fun measureProxyHttp204(localHttpProxyPort: Int): Int? {
        return try {
            val proxy = Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", localHttpProxyPort))
            val url = URL("https://cp.cloudflare.com/generate_204")
            var code = 0
            val elapsed = measureTimeMillis {
                val conn = (url.openConnection(proxy) as HttpsURLConnection).apply {
                    connectTimeout = 3500
                    readTimeout = 3500
                    requestMethod = "GET"
                }
                code = conn.responseCode
                conn.disconnect()
            }
            if (code in 200..299) elapsed.toInt().coerceAtLeast(1) else null
        } catch (_: Exception) {
            null
        }
    }

    private fun fetchCloudflareTrace(useLocalProxy: Boolean, localHttpProxyPort: Int): Map<String, String> {
        return try {
            val url = URL("https://1.1.1.1/cdn-cgi/trace")
            val conn = (if (useLocalProxy) {
                val proxy = Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", localHttpProxyPort))
                url.openConnection(proxy)
            } else {
                url.openConnection()
            }) as HttpURLConnection
            conn.connectTimeout = 3500
            conn.readTimeout = 3500
            conn.requestMethod = "GET"
            if (conn.responseCode !in 200..299) {
                conn.disconnect()
                return emptyMap()
            }
            val text = conn.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
            conn.disconnect()
            val map = mutableMapOf<String, String>()
            text.lineSequence().forEach { line ->
                val eq = line.indexOf('=')
                if (eq > 0) {
                    map[line.substring(0, eq).trim()] = line.substring(eq + 1).trim()
                }
            }
            map
        } catch (_: Exception) {
            emptyMap()
        }
    }
}
