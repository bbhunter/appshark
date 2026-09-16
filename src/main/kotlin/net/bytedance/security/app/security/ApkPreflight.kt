/*
 * Copyright 2022 Beijing Zitiao Network Technology Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.bytedance.security.app.security

import java.io.IOException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.util.zip.ZipException
import java.util.zip.ZipFile

data class ApkPreflightReport(
    val apkBytes: Long,
    val entryCount: Int,
    val totalUncompressedBytes: Long,
    val dexCount: Int,
    val dexBytes: Long,
)

internal fun checkUniqueEntry(seen: MutableSet<String>, name: String) {
    require(seen.add(name)) { "APK ZIP contains duplicate entry names" }
}

internal fun checkedAdd(current: Long, value: Long, description: String): Long =
    try {
        Math.addExact(current, value)
    } catch (e: ArithmeticException) {
        throw IllegalArgumentException("$description overflows supported size", e)
    }

object ApkPreflight {
    private val dexName = Regex("""(?:^|/)classes(?:\d+)?\.dex$""")

    fun inspect(apk: Path, limits: SecurityLimits): ApkPreflightReport {
        limits.validate()
        require(Files.isRegularFile(apk, LinkOption.NOFOLLOW_LINKS)) {
            "APK must be a regular file"
        }
        require(!Files.isSymbolicLink(apk)) { "APK must not be a symbolic link" }

        val apkBytes = Files.size(apk)
        require(apkBytes <= limits.maxApkBytes) {
            "APK exceeds maximum size of ${limits.maxApkBytes} bytes"
        }

        try {
            ZipFile(apk.toFile()).use { zip ->
                var entryCount = 0
                var totalUncompressedBytes = 0L
                var dexCount = 0
                var dexBytes = 0L
                val seen = HashSet<String>()
                val entries = zip.entries()

                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    entryCount = Math.addExact(entryCount, 1)
                    require(entryCount <= limits.maxZipEntries) {
                        "APK ZIP exceeds maximum entry count of ${limits.maxZipEntries}"
                    }
                    require(entry.name.length <= limits.maxZipEntryNameChars) {
                        "APK ZIP entry name exceeds maximum length"
                    }
                    checkUniqueEntry(seen, entry.name)
                    require(entry.size >= 0L) { "APK ZIP entry has unknown uncompressed size" }
                    require(entry.compressedSize >= 0L) {
                        "APK ZIP entry has unknown compressed size"
                    }
                    require(entry.size <= limits.maxZipEntryUncompressedBytes) {
                        "APK ZIP entry exceeds maximum uncompressed size"
                    }

                    totalUncompressedBytes = checkedAdd(
                        totalUncompressedBytes,
                        entry.size,
                        "APK ZIP total uncompressed size"
                    )
                    require(totalUncompressedBytes <= limits.maxZipTotalUncompressedBytes) {
                        "APK ZIP exceeds maximum total uncompressed size"
                    }

                    checkCompressionRatio(entry.size, entry.compressedSize, entry.isDirectory, limits)

                    if (dexName.matches(entry.name)) {
                        dexCount = Math.addExact(dexCount, 1)
                        require(dexCount <= limits.maxDexFiles) {
                            "APK exceeds maximum DEX file count of ${limits.maxDexFiles}"
                        }
                        dexBytes = checkedAdd(dexBytes, entry.size, "APK DEX total size")
                        require(dexBytes <= limits.maxDexTotalBytes) {
                            "APK exceeds maximum DEX total size"
                        }
                    }
                }

                return ApkPreflightReport(
                    apkBytes = apkBytes,
                    entryCount = entryCount,
                    totalUncompressedBytes = totalUncompressedBytes,
                    dexCount = dexCount,
                    dexBytes = dexBytes
                )
            }
        } catch (e: IllegalArgumentException) {
            throw e
        } catch (e: ArithmeticException) {
            throw IllegalArgumentException("APK ZIP metadata exceeds supported range", e)
        } catch (e: ZipException) {
            throw IllegalArgumentException("APK ZIP preflight failed: malformed archive", e)
        } catch (e: IOException) {
            throw IllegalArgumentException("APK ZIP preflight failed: unable to read archive", e)
        }
    }

    private fun checkCompressionRatio(
        uncompressedSize: Long,
        compressedSize: Long,
        directory: Boolean,
        limits: SecurityLimits
    ) {
        if (directory || uncompressedSize == 0L) {
            return
        }
        require(compressedSize > 0L) { "APK ZIP entry has invalid compressed size" }
        val allowedSize = try {
            Math.multiplyExact(compressedSize, limits.maxZipCompressionRatio)
        } catch (_: ArithmeticException) {
            Long.MAX_VALUE
        }
        require(uncompressedSize <= allowedSize) {
            "APK ZIP entry exceeds maximum compression ratio"
        }
    }
}
