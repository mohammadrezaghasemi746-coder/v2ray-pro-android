package com.v2raypro.android

import com.v2raypro.android.core.UriParser
import com.v2raypro.android.core.XrayConfigBuilder
import com.v2raypro.android.model.AntiLeakAndStaticIpConfig
import com.v2raypro.android.service.V2RayVpnService
import com.v2raypro.android.updater.OtaUpdateManager
import org.junit.Assert.*
import org.junit.Test
import java.net.InetAddress
import java.nio.ByteBuffer

class V2RayProUnitTest {

    @Test
    fun testParseVlessRealityAndRejectIncompleteReality() {
        val validUri = "vless://550e8400-e29b-41d4-a716-446655440000@198.51.100.42:443?security=reality&encryption=none&pbk=m1234567890abcdef&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=www.cloudflare.com&sid=a1b2#🇩🇪 آلمان ۱"
        val res = UriParser.parseSingleUri(validUri)
        assertTrue(res.isSuccess)
        val p = res.getOrThrow()
        assertEquals("vless", p.protocol)
        assertEquals("198.51.100.42", p.address)
        assertEquals(443, p.port)
        assertEquals("reality", p.security)
        assertEquals("xtls-rprx-vision", p.flow)
        assertEquals("🇩🇪 آلمان ۱", p.name)

        // Missing pbk must fail
        val invalidReality = "vless://550e8400-e29b-41d4-a716-446655440000@198.51.100.42:443?security=reality&sni=www.cloudflare.com#BadNode"
        assertTrue(UriParser.parseSingleUri(invalidReality).isFailure)
    }

    @Test
    fun testShadowsocksSip002AndLegacyParsing() {
        // SIP002 format: ss://BASE64(aes-256-gcm:secretpass)@198.51.100.10:8388#SS-Node
        val sip002 = "ss://YWVzLTI1Ni1nY206c2VjcmV0cGFzcw==@198.51.100.10:8388#SS-Node"
        val p1 = UriParser.parseSingleUri(sip002).getOrThrow()
        assertEquals("shadowsocks", p1.protocol)
        assertEquals("aes-256-gcm", p1.cipher)
        assertEquals("secretpass", p1.uuidOrPassword)
        assertEquals("198.51.100.10", p1.address)
        assertEquals(8388, p1.port)
    }

    @Test
    fun testLanExclusionCidrsCoverPublicIpsAndExcludePrivateLan() {
        fun ipToLong(ip: String): Long {
            val bytes = InetAddress.getByName(ip).address
            return ByteBuffer.wrap(bytes).int.toLong() and 0xFFFFFFFFL
        }

        fun matchesCidr(ip: String, cidrIp: String, prefix: Int): Boolean {
            val mask = if (prefix == 0) 0L else ((0xFFFFFFFFL shl (32 - prefix)) and 0xFFFFFFFFL)
            return (ipToLong(ip) and mask) == (ipToLong(cidrIp) and mask)
        }

        fun isRoutedToVpn(ip: String): Boolean =
            V2RayVpnService.PUBLIC_IPV4_ROUTES_EXCLUDING_LAN.any { (net, pfx) -> matchesCidr(ip, net, pfx) }

        // Private LAN, loopback, link-local, and multicast MUST NOT be routed into TUN
        assertFalse(isRoutedToVpn("192.168.1.1"))
        assertFalse(isRoutedToVpn("192.168.0.254"))
        assertFalse(isRoutedToVpn("10.0.0.1"))
        assertFalse(isRoutedToVpn("10.200.200.2"))
        assertFalse(isRoutedToVpn("172.16.0.1"))
        assertFalse(isRoutedToVpn("172.31.255.254"))
        assertFalse(isRoutedToVpn("169.254.10.20"))
        assertFalse(isRoutedToVpn("127.0.0.1"))
        assertFalse(isRoutedToVpn("224.0.0.251"))

        // Public internet IPs MUST be routed into TUN
        assertTrue(isRoutedToVpn("1.1.1.1"))
        assertTrue(isRoutedToVpn("8.8.8.8"))
        assertTrue(isRoutedToVpn("104.16.132.229"))
        assertTrue(isRoutedToVpn("185.199.108.153"))
    }

    @Test
    fun testXrayConfigBuilderLanBypassAndAlpn() {
        val uri = "vless://550e8400-e29b-41d4-a716-446655440000@example.com:443?security=tls&type=ws&host=cdn.example.com&path=%2Fws&alpn=h2,http/1.1#WS-Node"
        val profile = UriParser.parseSingleUri(uri).getOrThrow()
        val antiLeak = AntiLeakAndStaticIpConfig(routingMode = "bypass_lan")
        val jsonStr = XrayConfigBuilder.buildConfig(profile, antiLeak, emptyList(), serverIp = "93.184.216.34")
        assertTrue(jsonStr.contains("\"192.168.0.0/16\""))
        assertTrue(jsonStr.contains("\"h2\""))
        assertTrue(jsonStr.contains("\"93.184.216.34\""))
    }

    @Test
    fun testOtaSha256Verification() {
        val sample = "V2RayPro-Test-Payload".toByteArray()
        val digest = OtaUpdateManager.computeSha256Hex(sample)
        assertTrue(OtaUpdateManager.verifySha256(sample, digest))
        assertFalse(OtaUpdateManager.verifySha256(sample, "0".repeat(64)))
    }
}
