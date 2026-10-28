package com.v2raypro.android.core

import com.v2raypro.android.model.ServerProfile
import com.v2raypro.android.model.SubscriptionFeed
import com.v2raypro.android.model.SubscriptionSyncResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL
import java.util.UUID
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLException

/**
 * Real HTTPS Subscription Manager.
 * - Fetches subscription feeds directly over HTTPS/HTTP with configurable timeout and TLS validation.
 * - Never routes private subscription URLs through third-party CORS proxies.
 * - Parses Subscription-Userinfo headers for expiration checks.
 * - Atomically merges new/updated profiles while preserving stable profile IDs and user selection.
 * - Refuses to overwrite existing valid profiles if a refresh returns an empty/corrupted response.
 */
class SubscriptionManager(private val repository: StorageRepository) {

    suspend fun syncSubscriptionUrl(
        rawUrl: String,
        customName: String = "",
        connectTimeoutMs: Int = 8000,
        readTimeoutMs: Int = 10000
    ): SubscriptionSyncResult = withContext(Dispatchers.IO) {
        val cleanUrl = rawUrl.trim()
        if (!cleanUrl.startsWith("https://", ignoreCase = true) && !cleanUrl.startsWith("http://", ignoreCase = true)) {
            return@withContext SubscriptionSyncResult(
                subscriptionId = "",
                url = cleanUrl,
                success = false,
                errorReason = "Invalid subscription URL scheme (must start with https:// or http://)"
            )
        }

        val state = repository.loadState()
        val existingSub = state.subscriptions.firstOrNull { it.url.equals(cleanUrl, ignoreCase = true) }
        val subId = existingSub?.id ?: "sub_${UUID.randomUUID()}"
        val hostName = runCatching { URL(cleanUrl).host }.getOrDefault("Subscription")
        val subName = customName.ifBlank { existingSub?.name ?: "Sub ($hostName)" }

        var httpStatus = 0
        var responseBody = ""
        var userInfoHeader: String? = null

        try {
            val conn = (URL(cleanUrl).openConnection() as HttpURLConnection).apply {
                instanceFollowRedirects = true
                connectTimeout = connectTimeoutMs
                readTimeout = readTimeoutMs
                requestMethod = "GET"
                setRequestProperty("User-Agent", "V2RayPro-Android/2.2 (Xray-core)")
                setRequestProperty("Accept", "*/*")
            }
            if (conn is HttpsURLConnection) {
                conn.useCaches = false
            }
            httpStatus = conn.responseCode
            userInfoHeader = conn.getHeaderField("Subscription-Userinfo")
                ?: conn.getHeaderField("subscription-userinfo")

            if (httpStatus !in 200..299) {
                val reason = when (httpStatus) {
                    401, 403 -> "Subscription unauthorized or expired (HTTP $httpStatus)"
                    404 -> "Subscription link not found (HTTP 404)"
                    else -> "Server returned HTTP $httpStatus"
                }
                conn.disconnect()
                return@withContext SubscriptionSyncResult(
                    subscriptionId = subId,
                    url = cleanUrl,
                    success = false,
                    httpStatus = httpStatus,
                    totalActive = state.profiles.count { it.subscriptionId == subId },
                    errorReason = reason
                )
            }

            responseBody = conn.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
            conn.disconnect()
        } catch (sslEx: SSLException) {
            return@withContext SubscriptionSyncResult(
                subscriptionId = subId,
                url = cleanUrl,
                success = false,
                httpStatus = httpStatus,
                totalActive = state.profiles.count { it.subscriptionId == subId },
                errorReason = "TLS/SSL verification failed: ${sslEx.message}"
            )
        } catch (e: Exception) {
            return@withContext SubscriptionSyncResult(
                subscriptionId = subId,
                url = cleanUrl,
                success = false,
                httpStatus = httpStatus,
                totalActive = state.profiles.count { it.subscriptionId == subId },
                errorReason = "Network error: ${e.javaClass.simpleName} (${e.message ?: "unreachable"})"
            )
        }

        // Check expiration in Subscription-Userinfo header if present
        val expireDays = parseExpireDaysRemaining(userInfoHeader)
        if (expireDays != null && expireDays < 0) {
            return@withContext SubscriptionSyncResult(
                subscriptionId = subId,
                url = cleanUrl,
                success = false,
                httpStatus = httpStatus,
                expireDaysRemaining = expireDays,
                totalActive = state.profiles.count { it.subscriptionId == subId },
                errorReason = "Subscription has expired"
            )
        }

        val parsedProfiles = UriParser.decodeSubscriptionBatch(responseBody, subId)
        if (parsedProfiles.isEmpty()) {
            return@withContext SubscriptionSyncResult(
                subscriptionId = subId,
                url = cleanUrl,
                success = false,
                httpStatus = httpStatus,
                expireDaysRemaining = expireDays,
                totalActive = state.profiles.count { it.subscriptionId == subId },
                errorReason = "No valid VLESS/VMess/Trojan/SS configs found in subscription payload (existing configs preserved)"
            )
        }

        return@withContext mergeSubscriptionProfiles(
            subId = subId,
            subName = subName,
            cleanUrl = cleanUrl,
            httpStatus = httpStatus,
            expireDays = expireDays,
            fetchedProfiles = parsedProfiles
        )
    }

    fun mergeSubscriptionProfiles(
        subId: String,
        subName: String,
        cleanUrl: String,
        httpStatus: Int,
        expireDays: Int?,
        fetchedProfiles: List<ServerProfile>
    ): SubscriptionSyncResult {
        val state = repository.loadState()
        val otherProfiles = state.profiles.filter { it.subscriptionId != subId }
        val oldSubProfiles = state.profiles.filter { it.subscriptionId == subId }
        val oldByKey = oldSubProfiles.associateBy { it.stableEndpointKey() }

        var added = 0
        var updated = 0
        val mergedSubProfiles = mutableListOf<ServerProfile>()
        val seenKeys = mutableSetOf<String>()

        for (incoming in fetchedProfiles) {
            val key = incoming.stableEndpointKey()
            if (!seenKeys.add(key)) continue
            val existing = oldByKey[key]
            if (existing != null) {
                mergedSubProfiles.add(
                    incoming.copy(
                        id = existing.id,
                        latencyMs = existing.latencyMs,
                        lastTestStatus = existing.lastTestStatus
                    )
                )
                updated++
            } else {
                mergedSubProfiles.add(incoming)
                added++
            }
        }

        val removed = (oldSubProfiles.size - updated).coerceAtLeast(0)
        val allProfiles = otherProfiles + mergedSubProfiles

        // Preserve selectedProfileId if still valid, otherwise select first available
        val newSelectedId = if (allProfiles.any { it.id == state.selectedProfileId }) {
            state.selectedProfileId
        } else {
            allProfiles.firstOrNull()?.id
        }

        val nowSec = System.currentTimeMillis() / 1000L
        val updatedSub = SubscriptionFeed(
            id = subId,
            name = subName,
            url = cleanUrl,
            enabled = true,
            lastUpdatedEpochSec = nowSec,
            expireDaysRemaining = expireDays,
            lastSyncStatus = "OK (${mergedSubProfiles.size} nodes)"
        )
        val newSubs = state.subscriptions.filter { it.id != subId && !it.url.equals(cleanUrl, true) } + updatedSub

        repository.saveState(
            state.copy(
                profiles = allProfiles,
                subscriptions = newSubs,
                selectedProfileId = newSelectedId
            )
        )

        return SubscriptionSyncResult(
            subscriptionId = subId,
            url = cleanUrl,
            success = true,
            httpStatus = httpStatus,
            addedCount = added,
            updatedCount = updated,
            removedCount = removed,
            totalActive = mergedSubProfiles.size,
            expireDaysRemaining = expireDays,
            errorReason = null
        )
    }

    private fun parseExpireDaysRemaining(header: String?): Int? {
        if (header.isNullOrBlank()) return null
        val match = Regex("""expire=(\d+)""", RegexOption.IGNORE_CASE).find(header) ?: return null
        val expireEpochSec = match.groupValues[1].toLongOrNull() ?: return null
        if (expireEpochSec <= 0L) return null
        val nowSec = System.currentTimeMillis() / 1000L
        val diffSec = expireEpochSec - nowSec
        return if (diffSec < 0) -1 else (diffSec / 86400L).toInt()
    }
}
