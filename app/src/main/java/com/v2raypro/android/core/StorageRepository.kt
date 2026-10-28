package com.v2raypro.android.core

import android.content.Context
import com.v2raypro.android.model.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.File

/**
 * Atomic JSON state persistence for V2Ray Pro Android.
 * HARD REQUIREMENT: Starts with ZERO preloaded/demo server configs and ZERO demo subscriptions.
 * All servers must be imported by the user via URI, Clipboard, QR Code, or Subscription URL.
 */
class StorageRepository(private val context: Context) {
    private val json = Json { ignoreUnknownKeys = true; prettyPrint = true }
    private val stateFile = File(context.filesDir, "v2ray_pro_state.json")
    private val backupFile = File(context.filesDir, "v2ray_pro_state.json.bak")

    @kotlinx.serialization.Serializable
    data class PersistedState(
        val profiles: List<ServerProfile> = emptyList(), // STRICTLY EMPTY BY DEFAULT (NO DEMO CONFIGS)
        val subscriptions: List<SubscriptionFeed> = emptyList(), // STRICTLY EMPTY BY DEFAULT
        val selectedProfileId: String? = null,
        val antiLeakConfig: AntiLeakAndStaticIpConfig = AntiLeakAndStaticIpConfig(),
        val routingRules: List<RoutingRuleItem> = defaultZeroLeakRoutingRules()
    )

    companion object {
        fun defaultZeroLeakRoutingRules(): List<RoutingRuleItem> = listOf(
            RoutingRuleItem(
                id = "rule-webrtc-stun-block",
                name = "Block WebRTC STUN/TURN UDP Leak (3478, 5349, 19302)",
                enabled = true,
                ruleType = "port",
                matchExpression = "3478, 3479, 5349, 19302",
                outboundTag = "block"
            ),
            RoutingRuleItem(
                id = "rule-lan-direct",
                name = "Bypass Private LAN Subnets",
                enabled = true,
                ruleType = "ip",
                matchExpression = "127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16",
                outboundTag = "direct"
            ),
            RoutingRuleItem(
                id = "rule-ads-telemetry-block",
                name = "Block Ads & Tracking Domains",
                enabled = true,
                ruleType = "domain",
                matchExpression = "geosite:category-ads-all",
                outboundTag = "block"
            )
        )
    }

    @Synchronized
    fun loadState(): PersistedState {
        if (!stateFile.exists()) {
            return PersistedState()
        }
        return try {
            json.decodeFromString<PersistedState>(stateFile.readText())
        } catch (e: Exception) {
            if (backupFile.exists()) {
                runCatching { json.decodeFromString<PersistedState>(backupFile.readText()) }
                    .getOrDefault(PersistedState())
            } else {
                PersistedState()
            }
        }
    }

    @Synchronized
    fun saveState(state: PersistedState) {
        if (stateFile.exists()) {
            stateFile.copyTo(backupFile, overwrite = true)
        }
        val tmpFile = File(context.filesDir, "v2ray_pro_state.tmp")
        tmpFile.writeText(json.encodeToString(state))
        tmpFile.renameTo(stateFile)
    }
}
