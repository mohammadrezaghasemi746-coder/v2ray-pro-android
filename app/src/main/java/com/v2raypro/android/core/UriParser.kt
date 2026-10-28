package com.v2raypro.android.core

import android.util.Base64
import com.v2raypro.android.model.ServerProfile
import org.json.JSONObject
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

/**
 * Hardened V2Ray / Xray URI and Subscription Parser.
 * Supports VLESS, VMess, Trojan, and Shadowsocks (SIP002 & Legacy Base64).
 * Does not rely on strict java.net.URI for unescaped #remarks or query strings containing emojis/Persian text.
 */
object UriParser {

    val SUPPORTED_PROTOCOLS = setOf("vless", "vmess", "trojan", "shadowsocks")

    private val SUPPORTED_SS_CIPHERS = setOf(
        "aes-128-gcm",
        "aes-256-gcm",
        "chacha20-poly1305",
        "chacha20-ietf-poly1305",
        "xchacha20-poly1305",
        "xchacha20-ietf-poly1305",
        "2022-blake3-aes-128-gcm",
        "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305",
        "none",
        "plain"
    )

    fun parseSingleUri(rawUri: String, subscriptionId: String = "manual"): Result<ServerProfile> {
        val cleaned = rawUri.trim()
            .replace("&amp;", "&")
            .replace("&#39;", "'")
            .replace("&quot;", "\"")
        if (cleaned.isEmpty()) {
            return Result.failure(IllegalArgumentException("Empty URI string"))
        }

        return try {
            when {
                cleaned.startsWith("vless://", ignoreCase = true) ->
                    parseVlessOrTrojan(cleaned, "vless", subscriptionId)
                cleaned.startsWith("trojan://", ignoreCase = true) ->
                    parseVlessOrTrojan(cleaned, "trojan", subscriptionId)
                cleaned.startsWith("vmess://", ignoreCase = true) ->
                    parseVmess(cleaned, subscriptionId)
                cleaned.startsWith("ss://", ignoreCase = true) ->
                    parseShadowsocks(cleaned, subscriptionId)
                else ->
                    Result.failure(IllegalArgumentException("Unsupported or non-Xray protocol scheme: ${cleaned.substringBefore("://")}"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    private fun safeUrlDecode(value: String): String {
        return try {
            URLDecoder.decode(value.replace("+", "%2B"), StandardCharsets.UTF_8.name())
        } catch (_: Exception) {
            value
        }
    }

    fun tryDecodeBase64(input: String): String? {
        return try {
            var clean = input.trim().replace("\\s+".toRegex(), "").replace('-', '+').replace('_', '/')
            if (clean.length < 4 || clean.any { !it.isLetterOrDigit() && it != '+' && it != '/' && it != '=' }) {
                return null
            }
            while (clean.length % 4 != 0) clean += "="
            val bytes = Base64.decode(clean, Base64.DEFAULT)
            String(bytes, StandardCharsets.UTF_8)
        } catch (_: Exception) {
            null
        }
    }

    private fun splitHostAndPort(hostPort: String, defaultPort: Int): Pair<String, Int>? {
        val trimmed = hostPort.trim().trimEnd('/')
        if (trimmed.isEmpty()) return null
        return if (trimmed.startsWith("[")) {
            val closeIdx = trimmed.indexOf(']')
            if (closeIdx <= 1) return null
            val host = trimmed.substring(1, closeIdx)
            val portPart = trimmed.substring(closeIdx + 1).removePrefix(":")
            val port = if (portPart.isEmpty()) defaultPort else portPart.toIntOrNull() ?: return null
            if (port !in 1..65535) return null
            host to port
        } else {
            val colonIdx = trimmed.lastIndexOf(':')
            if (colonIdx > 0 && trimmed.indexOf(':') == colonIdx) {
                val host = trimmed.substring(0, colonIdx).trim()
                val port = trimmed.substring(colonIdx + 1).trim().toIntOrNull() ?: return null
                if (host.isEmpty() || port !in 1..65535) return null
                host to port
            } else if (colonIdx == -1) {
                trimmed to defaultPort
            } else {
                null
            }
        }
    }

    private fun parseQueryParams(query: String): Map<String, String> {
        if (query.isBlank()) return emptyMap()
        val map = mutableMapOf<String, String>()
        query.split("&").forEach { pair ->
            if (pair.isNotBlank()) {
                val eqIdx = pair.indexOf('=')
                if (eqIdx > 0) {
                    val key = pair.substring(0, eqIdx).trim().lowercase()
                    val value = safeUrlDecode(pair.substring(eqIdx + 1))
                    map[key] = value
                }
            }
        }
        return map
    }

    private fun parseVlessOrTrojan(uriStr: String, protocol: String, subId: String): Result<ServerProfile> {
        val afterScheme = uriStr.substringAfter("://")
        val beforeHash = afterScheme.substringBefore("#")
        val rawFragment = if (afterScheme.contains("#")) afterScheme.substringAfter("#") else ""

        val authorityAndPath = beforeHash.substringBefore("?")
        val rawQuery = if (beforeHash.contains("?")) beforeHash.substringAfter("?") else ""

        val atIdx = authorityAndPath.lastIndexOf('@')
        if (atIdx <= 0) {
            return Result.failure(IllegalArgumentException("Missing UUID/Password in $protocol URI"))
        }

        val userInfo = safeUrlDecode(authorityAndPath.substring(0, atIdx).trim())
        if (userInfo.isBlank()) {
            return Result.failure(IllegalArgumentException("Empty UUID/Password in $protocol URI"))
        }

        val hostPortPart = authorityAndPath.substring(atIdx + 1).substringBefore("/")
        val (host, port) = splitHostAndPort(hostPortPart, 443)
            ?: return Result.failure(IllegalArgumentException("Invalid host:port in $protocol URI"))

        val params = parseQueryParams(rawQuery)
        val remark = safeUrlDecode(rawFragment).trim().ifEmpty { "$protocol ($host:$port)" }

        val security = (params["security"] ?: if (protocol == "trojan") "tls" else "none").lowercase()
        val network = (params["type"] ?: params["net"] ?: "tcp").lowercase()

        if (security == "reality") {
            val pbk = params["pbk"].orEmpty()
            val sni = params["sni"].orEmpty()
            if (pbk.isBlank() || sni.isBlank()) {
                return Result.failure(IllegalArgumentException("REALITY config requires both 'pbk' and 'sni'"))
            }
        }

        val rawFlow = params["flow"].orEmpty()
        // XTLS Vision flow is only valid on TCP/XHTTP with TLS or REALITY
        val validFlow = if (protocol == "vless" && (security == "tls" || security == "reality") && (network == "tcp" || network == "xhttp")) {
            rawFlow
        } else {
            ""
        }

        val pathVal = when (network) {
            "grpc" -> params["servicename"] ?: params["path"] ?: ""
            else -> params["path"] ?: ""
        }

        return Result.success(
            ServerProfile(
                name = remark,
                protocol = protocol,
                address = host,
                port = port,
                uuidOrPassword = userInfo,
                flow = validFlow,
                network = network,
                headerType = params["headertype"] ?: "none",
                host = params["host"] ?: params["authority"] ?: "",
                path = pathVal,
                security = security,
                sni = params["sni"] ?: params["peer"] ?: params["host"] ?: host,
                alpn = params["alpn"]?.split(",")?.map { it.trim() }?.filter { it.isNotBlank() } ?: emptyList(),
                fingerprint = params["fp"]?.ifBlank { "chrome" } ?: "chrome",
                allowInsecure = params["allowinsecure"] == "1" || params["allowinsecure"].equals("true", true),
                pbk = params["pbk"] ?: "",
                sid = params["sid"] ?: "",
                spx = params["spx"] ?: "",
                staticExitIp = params["exit_ip"] ?: "",
                subscriptionId = subId,
                rawUri = uriStr
            )
        )
    }

    private fun parseVmess(uriStr: String, subId: String): Result<ServerProfile> {
        val afterScheme = uriStr.substringAfter("://").trim()
        val b64Part = afterScheme.substringBefore("#").substringBefore("?")
        val decoded = tryDecodeBase64(b64Part)
            ?: return Result.failure(IllegalArgumentException("Invalid Base64 in vmess:// URI"))
        val obj = JSONObject(decoded)
        val add = obj.optString("add").trim()
        val port = obj.optString("port", "443").toIntOrNull() ?: obj.optInt("port", 443)
        val id = obj.optString("id").trim()
        if (add.isBlank() || id.isBlank() || port !in 1..65535) {
            return Result.failure(IllegalArgumentException("VMess JSON missing valid 'add', 'port', or 'id'"))
        }
        val tlsField = obj.optString("tls", "").lowercase()
        val security = if (tlsField == "tls" || tlsField == "true") "tls" else "none"
        val net = obj.optString("net", "tcp").lowercase().ifBlank { "tcp" }
        val hostHeader = obj.optString("host", "").trim()
        val sni = obj.optString("sni", "").trim().ifBlank { hostHeader.ifBlank { add } }
        val alpnList = obj.optString("alpn", "")
            .split(",")
            .map { it.trim() }
            .filter { it.isNotBlank() }

        return Result.success(
            ServerProfile(
                name = obj.optString("ps", "").trim().ifBlank { "VMess ($add:$port)" },
                protocol = "vmess",
                address = add,
                port = port,
                uuidOrPassword = id,
                alterId = obj.optString("aid", "0").toIntOrNull() ?: obj.optInt("aid", 0),
                cipher = obj.optString("scy", "auto").ifBlank { "auto" },
                network = net,
                headerType = obj.optString("type", "none").ifBlank { "none" },
                host = hostHeader,
                path = obj.optString("path", ""),
                security = security,
                sni = sni,
                alpn = alpnList,
                fingerprint = obj.optString("fp", "chrome").ifBlank { "chrome" },
                subscriptionId = subId,
                rawUri = uriStr
            )
        )
    }

    private fun parseShadowsocks(uriStr: String, subId: String): Result<ServerProfile> {
        val afterScheme = uriStr.substringAfter("://").trim()
        val beforeHash = afterScheme.substringBefore("#")
        val rawFragment = if (afterScheme.contains("#")) afterScheme.substringAfter("#") else ""
        val beforeQuery = beforeHash.substringBefore("?")

        val credsPart: String
        val hostPortPart: String

        if (beforeQuery.contains("@")) {
            val atIdx = beforeQuery.lastIndexOf('@')
            val rawUser = beforeQuery.substring(0, atIdx)
            hostPortPart = beforeQuery.substring(atIdx + 1)
            credsPart = if (rawUser.contains(":")) safeUrlDecode(rawUser) else (tryDecodeBase64(rawUser) ?: safeUrlDecode(rawUser))
        } else {
            val decodedFull = tryDecodeBase64(beforeQuery)
                ?: return Result.failure(IllegalArgumentException("Invalid Base64 Shadowsocks URI"))
            val atIdx = decodedFull.lastIndexOf('@')
            if (atIdx <= 0) {
                return Result.failure(IllegalArgumentException("Missing '@host:port' in Shadowsocks URI"))
            }
            credsPart = decodedFull.substring(0, atIdx)
            hostPortPart = decodedFull.substring(atIdx + 1)
        }

        val colonIdx = credsPart.indexOf(':')
        if (colonIdx <= 0) {
            return Result.failure(IllegalArgumentException("Invalid Shadowsocks 'method:password' format"))
        }
        val method = credsPart.substring(0, colonIdx).trim().lowercase()
        val password = credsPart.substring(colonIdx + 1)
        if (method !in SUPPORTED_SS_CIPHERS || password.isEmpty()) {
            return Result.failure(IllegalArgumentException("Unsupported Shadowsocks cipher '$method' or empty password"))
        }

        val (host, port) = splitHostAndPort(hostPortPart, 8388)
            ?: return Result.failure(IllegalArgumentException("Invalid Shadowsocks host:port"))
        val remark = safeUrlDecode(rawFragment).trim().ifEmpty { "SS ($host:$port)" }

        return Result.success(
            ServerProfile(
                name = remark,
                protocol = "shadowsocks",
                address = host,
                port = port,
                cipher = method,
                uuidOrPassword = password,
                subscriptionId = subId,
                rawUri = uriStr
            )
        )
    }

    /**
     * Extracts all valid Xray ServerProfiles from any subscription payload:
     * - Plain multi-line URI list
     * - Base64-encoded subscription payload (standard or URL-safe, padded or unpadded)
     * - HTML subscription page containing embedded Base64 blocks or direct URI links
     */
    fun decodeSubscriptionBatch(rawPayload: String, subscriptionId: String = "manual"): List<ServerProfile> {
        if (rawPayload.isBlank()) return emptyList()
        val combined = StringBuilder(rawPayload.trim())

        // 1. Check if entire payload is a Base64 block
        tryDecodeBase64(rawPayload.trim())?.let { decoded ->
            if (decoded.contains("://")) {
                combined.append("\n").append(decoded)
            }
        }

        // 2. Scan for embedded Base64 blocks (e.g., inside HTML subscription pages)
        val b64TokenRegex = Regex("[A-Za-z0-9+/=_-]{40,}")
        b64TokenRegex.findAll(rawPayload).forEach { match ->
            val token = match.value
            if (!token.contains("://")) {
                tryDecodeBase64(token)?.let { dec ->
                    if (dec.contains("://")) {
                        combined.append("\n").append(dec)
                    }
                }
            }
        }

        val normalized = combined.toString()
            .replace("&amp;", "&")
            .replace("\\u0026", "&")
            .replace("\\/", "/")

        val uriRegex = Regex("""(?:vless|vmess|trojan|ss)://[^\s"'<>`\\]+""", RegexOption.IGNORE_CASE)
        val results = mutableListOf<ServerProfile>()
        val seenKeys = mutableSetOf<String>()

        uriRegex.findAll(normalized).forEach { match ->
            parseSingleUri(match.value, subscriptionId).getOrNull()?.let { profile ->
                val key = profile.stableEndpointKey()
                if (seenKeys.add(key)) {
                    results.add(profile)
                }
            }
        }

        return results
    }
}
