package com.v2raypro.android.model

import kotlinx.serialization.Serializable
import java.util.UUID

@Serializable
data class ServerProfile(
    val id: String = UUID.randomUUID().toString(),
    val name: String,
    val protocol: String, // vless, vmess, trojan, shadowsocks
    val address: String,
    val port: Int = 443,
    val uuidOrPassword: String,
    val alterId: Int = 0,
    val cipher: String = "auto",
    val flow: String = "",
    val network: String = "tcp", // tcp, ws, grpc, httpupgrade, xhttp
    val headerType: String = "none",
    val host: String = "",
    val path: String = "",
    val security: String = "none", // none, tls, reality
    val sni: String = "",
    val alpn: List<String> = emptyList(),
    val fingerprint: String = "chrome",
    val allowInsecure: Boolean = false,
    val pbk: String = "",
    val sid: String = "",
    val spx: String = "",
    val subscriptionId: String = "manual",
    val latencyMs: Int? = null,
    val lastTestStatus: String = "Untested",
    val staticExitIp: String = "",
    val rawUri: String = ""
) {
    /**
     * Stable identity key used to deduplicate profiles and preserve IDs across subscription updates.
     */
    fun stableEndpointKey(): String =
        "${protocol.lowercase()}|${address.lowercase()}|$port|$uuidOrPassword|${network.lowercase()}|${security.lowercase()}|${sni.lowercase()}|$path"

    /**
     * Redacts sensitive UUID/password for safe logging in Logcat.
     */
    fun redactedSummary(): String =
        "$name [$protocol://${address}:$port net=$network sec=$security]"
}

@Serializable
data class SubscriptionFeed(
    val id: String = UUID.randomUUID().toString(),
    val name: String,
    val url: String,
    val enabled: Boolean = true,
    val autoUpdateIntervalHours: Int = 6,
    val lastUpdatedEpochSec: Long = 0L,
    val expireDaysRemaining: Int? = null,
    val lastSyncStatus: String = "Never Synced"
)

@Serializable
data class AntiLeakAndStaticIpConfig(
    val enforceStaticTunIp: Boolean = true,
    val staticTunIpv4: String = "10.200.200.2",
    val staticTunPrefixLength: Int = 30,
    val staticTunGateway: String = "10.200.200.1",
    val bindDedicatedExitIp: String = "",
    val blockIpv6Leak: Boolean = true,
    val enforceRemoteDoH: Boolean = true,
    val remoteDohServer: String = "https://1.1.1.1/dns-query",
    val blockWebRtcStunLeak: Boolean = true,
    val strictKillSwitch: Boolean = true,
    /**
     * Routing policy:
     * - "bypass_lan": Route internet via VPN while keeping RFC1918 LAN & local gateway direct
     * - "iran_direct": Bypass private LAN + domestic .ir / geoip:ir traffic
     * - "all_tunnel": Route all traffic through VPN (excluding loopback/multicast)
     * - "block_ads": Bypass LAN + block ad/tracker domains
     */
    val routingMode: String = "bypass_lan",
    val domainStrategy: String = "IPIfNonMatch"
)

@Serializable
data class RoutingRuleItem(
    val id: String = UUID.randomUUID().toString(),
    val name: String,
    val enabled: Boolean = true,
    val ruleType: String, // domain, ip, port, protocol
    val matchExpression: String,
    val outboundTag: String // proxy, direct, block
)

@Serializable
data class PingResult(
    val profileId: String,
    val name: String,
    val host: String,
    val port: Int,
    /** "OK", "DNS_ERROR", "TIMEOUT", "REFUSED", "UNREACHABLE" */
    val status: String,
    /** Real measured latency in ms, or null if failed (never 0 or fake) */
    val latencyMs: Int? = null,
    /** "TCP_DIRECT" or "TUNNEL_HTTP204" */
    val method: String = "TCP_DIRECT",
    val errorDetail: String? = null
)

@Serializable
data class SubscriptionSyncResult(
    val subscriptionId: String,
    val url: String,
    val success: Boolean,
    val httpStatus: Int = 0,
    val addedCount: Int = 0,
    val updatedCount: Int = 0,
    val removedCount: Int = 0,
    val totalActive: Int = 0,
    val expireDaysRemaining: Int? = null,
    val errorReason: String? = null
)

@Serializable
data class NetworkTestReport(
    val timestampMs: Long,
    val tcpLatencyMs: Int?,
    val http204LatencyMs: Int?,
    val jitterMs: Int?,
    val downloadMbps: Double,
    val uploadMbps: Double,
    val detectedExitIp: String,
    val detectedLocation: String = "",
    val staticIpVerified: Boolean,
    val ipv4LeakDetected: Boolean,
    val ipv6LeakDetected: Boolean,
    val dnsLeakDetected: Boolean,
    val webRtcStunBlocked: Boolean,
    val lanGatewayReachable: Boolean = true,
    val overallGrade: String
)
