package com.v2raypro.android.core

import com.v2raypro.android.model.*
import org.json.JSONArray
import org.json.JSONObject

object XrayConfigBuilder {

    val PRIVATE_LAN_CIDRS = listOf(
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "100.64.0.0/10",
        "224.0.0.0/4",
        "255.255.255.255/32"
    )

    fun buildConfig(
        profile: ServerProfile,
        antiLeak: AntiLeakAndStaticIpConfig,
        routingRules: List<RoutingRuleItem>,
        socksPort: Int = 10808,
        httpPort: Int = 10809,
        /** Resolved IP of the proxy server (resolved BEFORE the tunnel is up) to avoid DNS-over-tunnel deadlock. */
        serverIp: String? = null,
        /** geosite.dat / geoip.dat present? Rules using geosite:/geoip: crash Xray at start when missing. */
        geoAssetsAvailable: Boolean = false
    ): String {
        require(profile.protocol in UriParser.SUPPORTED_PROTOCOLS) {
            "Unsupported Xray outbound protocol: ${profile.protocol}"
        }
        val root = JSONObject()

        // 1. Log Configuration
        root.put("log", JSONObject().apply {
            put("loglevel", "warning")
            put("dnsLog", false)
        })

        // 2. Anti-Leak DNS Configuration
        root.put("dns", JSONObject().apply {
            put("queryStrategy", if (antiLeak.blockIpv6Leak) "UseIPv4" else "UseIP")
            put("disableCache", false)
            if (!serverIp.isNullOrBlank() && serverIp != profile.address) {
                put("hosts", JSONObject().put(profile.address, serverIp))
            }
            put("servers", JSONArray().apply {
                if (antiLeak.enforceRemoteDoH && antiLeak.remoteDohServer.isNotBlank()) {
                    put(antiLeak.remoteDohServer)
                } else {
                    put("1.1.1.1")
                }
                put("1.0.0.1")
                put("8.8.8.8")
            })
        })

        // 3. Inbounds (Native TUN + Local Loopback SOCKS5 & HTTP)
        root.put("inbounds", JSONArray().apply {
            put(JSONObject().apply {
                put("tag", "tun-in")
                put("protocol", "tun")
                put("settings", JSONObject().apply {
                    put("name", "xray0")
                    put("MTU", 1500)
                    put("userLevel", 0)
                })
                put("sniffing", JSONObject().apply {
                    put("enabled", true)
                    put("destOverride", JSONArray().put("http").put("tls").put("quic"))
                })
            })
            put(JSONObject().apply {
                put("tag", "socks-in")
                put("port", socksPort)
                put("listen", "127.0.0.1")
                put("protocol", "socks")
                put("settings", JSONObject().apply {
                    put("auth", "noauth")
                    put("udp", true)
                })
                put("sniffing", JSONObject().apply {
                    put("enabled", true)
                    put("destOverride", JSONArray().put("http").put("tls").put("quic"))
                    put("routeOnly", true)
                })
            })
            put(JSONObject().apply {
                put("tag", "http-in")
                put("port", httpPort)
                put("listen", "127.0.0.1")
                put("protocol", "http")
            })
        })

        // 4. Outbounds (Proxy + Direct + Block + DNS-Out)
        val proxyOutbound = JSONObject().apply {
            put("tag", "proxy")
            put("protocol", profile.protocol.lowercase())
            if (antiLeak.bindDedicatedExitIp.isNotBlank()) {
                put("sendThrough", antiLeak.bindDedicatedExitIp)
            }
            put("settings", buildProtocolSettings(profile))
            put("streamSettings", buildStreamSettings(profile))
        }

        val directOutbound = JSONObject().apply {
            put("tag", "direct")
            put("protocol", "freedom")
            put("settings", JSONObject().apply {
                put("domainStrategy", if (antiLeak.blockIpv6Leak) "UseIPv4" else "AsIs")
            })
        }

        val blockOutbound = JSONObject().apply {
            put("tag", "block")
            put("protocol", "blackhole")
            put("settings", JSONObject().apply {
                put("response", JSONObject().put("type", "none"))
            })
        }

        val dnsOutbound = JSONObject().apply {
            put("tag", "dns-out")
            put("protocol", "dns")
        }

        root.put("outbounds", JSONArray().apply {
            put(proxyOutbound)
            put(directOutbound)
            put(blockOutbound)
            put(dnsOutbound)
        })

        // 5. Routing Engine (DNS hijack, WebRTC block, IPv6 guard, LAN preservation, and mode rules)
        val rulesArray = JSONArray()

        // Hijack port 53 to dns-out to prevent plain UDP DNS leaks
        rulesArray.put(JSONObject().apply {
            put("type", "field")
            put("inboundTag", JSONArray().put("tun-in").put("socks-in").put("http-in"))
            put("port", 53)
            put("outboundTag", "dns-out")
        })

        // Block WebRTC STUN/TURN UDP ports to prevent real IP leak in browsers/WebViews
        if (antiLeak.blockWebRtcStunLeak) {
            rulesArray.put(JSONObject().apply {
                put("type", "field")
                put("network", "udp")
                put("port", "3478,3479,5349,19302")
                put("outboundTag", "block")
            })
        }

        // Block IPv6 traffic completely if IPv6 Leak Guard is enabled
        if (antiLeak.blockIpv6Leak) {
            rulesArray.put(JSONObject().apply {
                put("type", "field")
                put("ip", JSONArray().put("::/0"))
                put("outboundTag", "block")
            })
        }

        // Preserve direct access to private LAN subnets unless user explicitly chose strict all_tunnel without LAN
        if (antiLeak.routingMode != "all_tunnel") {
            val lanIps = JSONArray()
            PRIVATE_LAN_CIDRS.forEach { lanIps.put(it) }
            rulesArray.put(JSONObject().apply {
                put("type", "field")
                put("ip", lanIps)
                put("outboundTag", "direct")
            })
        }

        if (antiLeak.routingMode == "iran_direct") {
            val irDomains = JSONArray().put("regexp:.*\\.ir$")
            if (geoAssetsAvailable) irDomains.put("geosite:ir")
            rulesArray.put(JSONObject().apply {
                put("type", "field")
                put("domain", irDomains)
                put("outboundTag", "direct")
            })
            if (geoAssetsAvailable) {
                rulesArray.put(JSONObject().apply {
                    put("type", "field")
                    put("ip", JSONArray().put("geoip:ir"))
                    put("outboundTag", "direct")
                })
            }
        }

        if (antiLeak.routingMode == "block_ads" && geoAssetsAvailable) {
            rulesArray.put(JSONObject().apply {
                put("type", "field")
                put("domain", JSONArray().put("geosite:category-ads-all"))
                put("outboundTag", "block")
            })
        }

        // User custom routing rules
        routingRules.filter { it.enabled }.filter { rule ->
            geoAssetsAvailable || (!rule.matchExpression.contains("geosite:") && !rule.matchExpression.contains("geoip:"))
        }.forEach { rule ->
            rulesArray.put(JSONObject().apply {
                put("type", "field")
                put("outboundTag", rule.outboundTag)
                val tokens = JSONArray()
                rule.matchExpression.split(",").map { it.trim() }.filter { it.isNotEmpty() }.forEach { tokens.put(it) }
                when (rule.ruleType) {
                    "domain" -> put("domain", tokens)
                    "ip" -> put("ip", tokens)
                    "port" -> put("port", rule.matchExpression.replace(" ", ""))
                    "protocol" -> put("protocol", tokens)
                }
            })
        }

        val strategy = antiLeak.domainStrategy.takeIf {
            it in setOf("AsIs", "IPIfNonMatch", "IPOnDemand")
        } ?: "IPIfNonMatch"

        root.put("routing", JSONObject().apply {
            put("domainStrategy", strategy)
            put("rules", rulesArray)
        })

        return root.toString(2)
    }

    private fun buildProtocolSettings(p: ServerProfile): JSONObject {
        return when (p.protocol.lowercase()) {
            "vless" -> JSONObject().apply {
                put("vnext", JSONArray().put(JSONObject().apply {
                    put("address", p.address)
                    put("port", p.port)
                    put("users", JSONArray().put(JSONObject().apply {
                        put("id", p.uuidOrPassword)
                        put("encryption", "none")
                        if (p.flow.isNotBlank() && (p.network == "tcp" || p.network == "xhttp") && (p.security == "tls" || p.security == "reality")) {
                            put("flow", p.flow)
                        }
                    }))
                }))
            }
            "vmess" -> JSONObject().apply {
                put("vnext", JSONArray().put(JSONObject().apply {
                    put("address", p.address)
                    put("port", p.port)
                    put("users", JSONArray().put(JSONObject().apply {
                        put("id", p.uuidOrPassword)
                        put("alterId", p.alterId)
                        put("security", p.cipher.ifBlank { "auto" })
                    }))
                }))
            }
            "trojan" -> JSONObject().apply {
                put("servers", JSONArray().put(JSONObject().apply {
                    put("address", p.address)
                    put("port", p.port)
                    put("password", p.uuidOrPassword)
                }))
            }
            "shadowsocks" -> JSONObject().apply {
                put("servers", JSONArray().put(JSONObject().apply {
                    put("address", p.address)
                    put("port", p.port)
                    put("method", if (p.cipher.isBlank() || p.cipher == "auto") "aes-256-gcm" else p.cipher)
                    put("password", p.uuidOrPassword)
                }))
            }
            else -> throw IllegalArgumentException("Unsupported Xray protocol: ${p.protocol}")
        }
    }

    private fun buildStreamSettings(p: ServerProfile): JSONObject {
        return JSONObject().apply {
            val net = p.network.lowercase().ifBlank { "tcp" }
            val sec = p.security.lowercase().ifBlank { "none" }
            put("network", net)
            put("security", sec)

            if (sec == "tls") {
                put("tlsSettings", JSONObject().apply {
                    put("serverName", p.sni.ifBlank { p.host.ifBlank { p.address } })
                    put("allowInsecure", p.allowInsecure)
                    put("fingerprint", p.fingerprint.ifBlank { "chrome" })
                    if (p.alpn.isNotEmpty()) {
                        val alpnArr = JSONArray()
                        p.alpn.forEach { alpnArr.put(it) }
                        put("alpn", alpnArr)
                    }
                })
            } else if (sec == "reality") {
                put("realitySettings", JSONObject().apply {
                    put("serverName", p.sni.ifBlank { p.address })
                    put("fingerprint", p.fingerprint.ifBlank { "chrome" })
                    put("publicKey", p.pbk)
                    put("shortId", p.sid)
                    put("spiderX", p.spx.ifBlank { "/" })
                })
            }

            when (net) {
                "tcp" -> {
                    if (p.headerType.equals("http", ignoreCase = true)) {
                        put("tcpSettings", JSONObject().apply {
                            put("header", JSONObject().apply {
                                put("type", "http")
                                put("request", JSONObject().apply {
                                    put("path", JSONArray().put(p.path.ifBlank { "/" }))
                                    if (p.host.isNotBlank()) {
                                        put("headers", JSONObject().put("Host", JSONArray().put(p.host)))
                                    }
                                })
                            })
                        })
                    }
                }
                "ws" -> put("wsSettings", JSONObject().apply {
                    put("path", p.path.ifBlank { "/" })
                    val wsHost = p.host.ifBlank { p.sni }
                    if (wsHost.isNotBlank()) put("headers", JSONObject().put("Host", wsHost))
                })
                "grpc" -> put("grpcSettings", JSONObject().apply {
                    put("serviceName", p.path)
                    put("multiMode", false)
                    if (p.host.isNotBlank()) put("authority", p.host)
                })
                "httpupgrade" -> put("httpupgradeSettings", JSONObject().apply {
                    put("path", p.path.ifBlank { "/" })
                    if (p.host.isNotBlank()) put("host", p.host)
                })
                "xhttp", "splithttp" -> put("xhttpSettings", JSONObject().apply {
                    put("path", p.path.ifBlank { "/" })
                    if (p.host.isNotBlank()) put("host", p.host)
                })
            }
        }
    }
}
