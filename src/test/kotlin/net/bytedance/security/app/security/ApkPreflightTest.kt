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

import net.bytedance.security.app.security.SecurityTestFixtures.testLimits
import net.bytedance.security.app.security.SecurityTestFixtures.zipOf
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assumptions.assumeFalse
import org.junit.jupiter.api.Test
import java.nio.file.Files

internal class ApkPreflightTest {
    @Test
    fun `normal apk-like zip passes`() {
        val apk = zipOf(
            "AndroidManifest.xml" to byteArrayOf(1, 2),
            "classes.dex" to ByteArray(32) { it.toByte() },
            "res/raw/data.bin" to ByteArray(64) { it.toByte() }
        )

        val report = ApkPreflight.inspect(apk, testLimits())

        assertEquals(3, report.entryCount)
        assertEquals(98, report.totalUncompressedBytes)
        assertEquals(1, report.dexCount)
        assertEquals(32, report.dexBytes)
    }

    @Test
    fun `non zip input is rejected`() {
        val input = Files.createTempFile("appshark-not-zip", ".apk")
        Files.writeString(input, "not a zip")

        assertThrows(IllegalArgumentException::class.java) {
            ApkPreflight.inspect(input, testLimits())
        }
    }

    @Test
    fun `symbolic link apk is rejected`() {
        assumeFalse(System.getProperty("os.name").startsWith("Windows"))
        val target = zipOf("classes.dex" to ByteArray(8))
        val link = target.parent.resolve("linked-${target.fileName}")
        Files.createSymbolicLink(link, target)

        assertThrows(IllegalArgumentException::class.java) {
            ApkPreflight.inspect(link, testLimits())
        }
    }

    @Test
    fun `apk byte limit is enforced`() {
        val apk = zipOf("classes.dex" to ByteArray(128) { it.toByte() })

        assertThrows(IllegalArgumentException::class.java) {
            ApkPreflight.inspect(apk, testLimits(maxApkBytes = 32))
        }
    }

    @Test
    fun `zip entry count and size budgets are enforced`() {
        val apk = zipOf(
            "classes.dex" to ByteArray(32) { it.toByte() },
            "classes2.dex" to ByteArray(32) { it.toByte() }
        )

        assertThrows(IllegalArgumentException::class.java) {
            ApkPreflight.inspect(apk, testLimits(maxZipEntries = 1))
        }
        assertThrows(IllegalArgumentException::class.java) {
            ApkPreflight.inspect(
                apk,
                testLimits(
                    maxZipEntryUncompressedBytes = 31,
                    maxZipTotalUncompressedBytes = 64,
                    maxDexTotalBytes = 64
                )
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            ApkPreflight.inspect(
                apk,
                testLimits(
                    maxZipEntryUncompressedBytes = 64,
                    maxZipTotalUncompressedBytes = 63,
                    maxDexTotalBytes = 63
                )
            )
        }
    }

    @Test
    fun `high compression ratio is rejected`() {
        val apk = zipOf("assets/zeros.bin" to ByteArray(4096))

        assertThrows(IllegalArgumentException::class.java) {
            ApkPreflight.inspect(
                apk,
                testLimits(
                    maxZipEntryUncompressedBytes = 8192,
                    maxZipTotalUncompressedBytes = 8192,
                    maxZipCompressionRatio = 2,
                    maxDexTotalBytes = 8192
                )
            )
        }
    }

    @Test
    fun `dex count and total size budgets are enforced`() {
        val apk = zipOf(
            "classes.dex" to ByteArray(32) { it.toByte() },
            "classes2.dex" to ByteArray(32) { it.toByte() }
        )

        assertThrows(IllegalArgumentException::class.java) {
            ApkPreflight.inspect(apk, testLimits(maxDexFiles = 1))
        }
        assertThrows(IllegalArgumentException::class.java) {
            ApkPreflight.inspect(apk, testLimits(maxDexTotalBytes = 63))
        }
    }

    @Test
    fun `duplicate entry helper rejects the second name`() {
        val seen = mutableSetOf<String>()
        checkUniqueEntry(seen, "classes.dex")

        assertThrows(IllegalArgumentException::class.java) {
            checkUniqueEntry(seen, "classes.dex")
        }
    }

    @Test
    fun `checked size addition converts overflow to input error`() {
        assertThrows(IllegalArgumentException::class.java) {
            checkedAdd(Long.MAX_VALUE, 1, "ZIP uncompressed size")
        }
    }
}
