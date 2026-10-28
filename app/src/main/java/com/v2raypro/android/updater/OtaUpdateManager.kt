package com.v2raypro.android.updater

import org.json.JSONObject
import java.io.File
import java.security.MessageDigest

/**
 * Periodic OTA Update Manager for V2Ray Pro Android.
 * Enforces strict cryptographic SHA-256 verification and APK header validation
 * before accepting any update package or routing database.
 */
object OtaUpdateManager {

    data class UpdateManifest(
        val appVersionName: String,
        val appVersionCode: Int,
        val xrayCoreVersion: String,
        val geoAssetsVersion: String,
        val apkDownloadUrl: String,
        val apkSha256: String,
        val changelog: List<String>
    )

    fun computeSha256Hex(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return digest.joinToString("") { "%02x".format(it) }
    }

    fun verifySha256(bytes: ByteArray, expectedHex: String): Boolean {
        val cleanExpected = expectedHex.trim().lowercase()
        if (cleanExpected.length != 64 || !cleanExpected.all { it in '0'..'9' || it in 'a'..'f' }) {
            return false
        }
        return computeSha256Hex(bytes) == cleanExpected
    }

    /**
     * Validates that a downloaded APK file is non-empty, has a valid ZIP/APK local file header (PK\x03\x04),
     * and matches the expected SHA-256 digest from the release manifest.
     */
    fun validateDownloadedApk(apkFile: File, expectedSha256: String): Result<Unit> {
        if (!apkFile.exists() || !apkFile.isFile || apkFile.length() < 4096L) {
            return Result.failure(IllegalArgumentException("OTA APK file is missing or truncated (< 4 KB)"))
        }
        val bytes = apkFile.readBytes()
        if (bytes.size < 4 || bytes[0] != 0x50.toByte() || bytes[1] != 0x4B.toByte() ||
            bytes[2] != 0x03.toByte() || bytes[3] != 0x04.toByte()
        ) {
            return Result.failure(IllegalArgumentException("Invalid APK magic header (not a valid ZIP/APK archive)"))
        }
        if (!verifySha256(bytes, expectedSha256)) {
            return Result.failure(SecurityException("OTA APK SHA-256 checksum mismatch"))
        }
        return Result.success(Unit)
    }

    fun parseManifestJson(rawJson: String): Result<UpdateManifest> {
        return try {
            val obj = JSONObject(rawJson)
            val versionName = obj.optString("appVersionName", "").trim()
            val versionCode = obj.optInt("appVersionCode", -1)
            val coreVer = obj.optString("xrayCoreVersion", "").trim()
            val geoVer = obj.optString("geoAssetsVersion", "").trim()
            val url = obj.optString("apkDownloadUrl", "").trim()
            val sha = obj.optString("apkSha256", "").trim()

            if (versionName.isEmpty() || versionCode <= 0 || sha.length != 64) {
                return Result.failure(IllegalArgumentException("Incomplete or invalid OTA manifest JSON"))
            }
            val notes = mutableListOf<String>()
            val arr = obj.optJSONArray("changelog")
            if (arr != null) {
                for (i in 0 until arr.length()) {
                    notes.add(arr.optString(i))
                }
            }
            Result.success(
                UpdateManifest(
                    appVersionName = versionName,
                    appVersionCode = versionCode,
                    xrayCoreVersion = coreVer,
                    geoAssetsVersion = geoVer,
                    apkDownloadUrl = url,
                    apkSha256 = sha,
                    changelog = notes
                )
            )
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
