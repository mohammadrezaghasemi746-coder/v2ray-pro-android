package com.v2raypro.android.service

import android.content.Context
import java.lang.reflect.Proxy

/**
 * Validated wrapper around libv2ray.aar (2dust/AndroidLibXrayLite).
 *
 * Official AAR APIs:
 *   - libv2ray.Libv2ray.initCoreEnv(String envPath, String key)
 *   - libv2ray.Libv2ray.newCoreController(CoreCallbackHandler) -> CoreController
 *   - libv2ray.Libv2ray.checkVersionX() -> String
 *   - libv2ray.Libv2ray.measureOutboundDelay(String configJson, String url) -> long
 *   - libv2ray.CoreController.startLoop(String config, int tunFd)
 *   - libv2ray.CoreController.stopLoop()
 *   - libv2ray.CoreController.getIsRunning() -> boolean
 *   - libv2ray.CoreController.queryStats(String tag, String link) -> long
 */
class XrayCoreRunner(private val context: Context) {

    @Volatile
    private var controller: Any? = null

    val isRunning: Boolean
        get() {
            val c = controller ?: return false
            return runCatching {
                val m = c.javaClass.methods.firstOrNull { it.name.equals("getIsRunning", true) && it.parameterCount == 0 }
                (m?.invoke(c) as? Boolean) ?: true
            }.getOrDefault(false)
        }

    fun isNativeCoreAvailable(): Boolean {
        return try {
            Class.forName("libv2ray.Libv2ray")
            true
        } catch (_: Throwable) {
            false
        }
    }

    fun getCoreVersion(): String {
        return try {
            val libClass = Class.forName("libv2ray.Libv2ray")
            val m = libClass.methods.firstOrNull { it.name.equals("checkVersionX", true) && it.parameterCount == 0 }
            (m?.invoke(null) as? String) ?: "Xray-core (libv2ray)"
        } catch (_: Throwable) {
            "Not Bundled (Missing libv2ray.aar)"
        }
    }

    fun start(configJson: String, tunFd: Int) {
        val libClass = try {
            Class.forName("libv2ray.Libv2ray")
        } catch (e: Throwable) {
            throw IllegalStateException(
                "Xray native core (libv2ray.aar / libgojni.so) is not bundled in this APK. Place libv2ray.aar in app/libs/ and build with Gradle."
            )
        }

        runCatching {
            libClass.getMethod("initCoreEnv", String::class.java, String::class.java)
                .invoke(null, context.filesDir.absolutePath, "")
        }

        val handlerClass = Class.forName("libv2ray.CoreCallbackHandler")
        val handler = Proxy.newProxyInstance(handlerClass.classLoader, arrayOf(handlerClass)) { _, method, _ ->
            when (method.returnType) {
                java.lang.Long.TYPE -> 0L
                java.lang.Integer.TYPE -> 0
                java.lang.Boolean.TYPE -> true
                else -> null
            }
        }

        val ctrl = libClass.getMethod("newCoreController", handlerClass).invoke(null, handler)
            ?: throw IllegalStateException("Libv2ray.newCoreController returned null")
        val ctrlClass = ctrl.javaClass

        val withFd = ctrlClass.methods.firstOrNull {
            it.name.equals("startLoop", true) && it.parameterTypes.size == 2 &&
                it.parameterTypes[0] == String::class.java
        }
        val configOnly = ctrlClass.methods.firstOrNull {
            it.name.equals("startLoop", true) && it.parameterTypes.size == 1 &&
                it.parameterTypes[0] == String::class.java
        }

        try {
            when {
                withFd != null -> {
                    val fdArg: Any = if (withFd.parameterTypes[1] == java.lang.Long.TYPE) tunFd.toLong() else tunFd
                    withFd.invoke(ctrl, configJson, fdArg)
                }
                configOnly != null -> throw IllegalStateException(
                    "Incompatible libv2ray.aar: startLoop(String) does not accept a TUN file descriptor. Use AndroidLibXrayLite with native TUN inbound support."
                )
                else -> throw IllegalStateException("startLoop() method not found on CoreController")
            }
        } catch (e: java.lang.reflect.InvocationTargetException) {
            throw IllegalStateException(e.targetException?.message ?: "Xray startLoop failed", e.targetException)
        }

        controller = ctrl
        if (!isRunning) {
            controller = null
            throw IllegalStateException("Xray core exited immediately after startLoop()")
        }
    }

    fun measureOutboundDelay(configJson: String, testUrl: String = "https://cp.cloudflare.com/generate_204"): Long? {
        return try {
            val libClass = Class.forName("libv2ray.Libv2ray")
            val m = libClass.getMethod("measureOutboundDelay", String::class.java, String::class.java)
            val delay = (m.invoke(null, configJson, testUrl) as? Number)?.toLong()
            if (delay != null && delay > 0L) delay else null
        } catch (_: Throwable) {
            null
        }
    }

    fun stop() {
        val c = controller ?: return
        controller = null
        runCatching {
            c.javaClass.methods.firstOrNull { it.name.equals("stopLoop", true) }?.invoke(c)
        }
    }
}
