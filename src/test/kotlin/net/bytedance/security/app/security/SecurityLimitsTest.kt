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

import net.bytedance.security.app.ArgumentConfig
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

internal class SecurityLimitsTest {
    @Test
    fun `argument config uses approved secure defaults`() {
        val limits = ArgumentConfig(apkPath = "app.apk").securityLimits

        assertEquals(2L * 1024 * 1024 * 1024, limits.maxApkBytes)
        assertEquals(200_000, limits.maxZipEntries)
        assertEquals(8L * 1024 * 1024 * 1024, limits.maxZipTotalUncompressedBytes)
        assertEquals(4_096, limits.maxRuleFiles)
        assertEquals(100_000, limits.maxTotalAnalyzers)
        assertEquals(14_400, limits.maxScanSeconds)
        assertEquals(16, limits.maxJadxThreads)
        assertEquals(2L * 1024 * 1024 * 1024, limits.maxReportBytes)
    }

    @Test
    fun `zero and negative limits fail closed`() {
        assertThrows(IllegalArgumentException::class.java) {
            SecurityLimits(maxZipEntries = 0).validate()
        }
        assertThrows(IllegalArgumentException::class.java) {
            SecurityLimits(maxLogBytes = -1).validate()
        }
    }

    @Test
    fun `internally inconsistent limits fail closed`() {
        assertThrows(IllegalArgumentException::class.java) {
            SecurityLimits(
                maxZipEntryUncompressedBytes = 1024,
                maxZipTotalUncompressedBytes = 512
            ).validate()
        }
        assertThrows(IllegalArgumentException::class.java) {
            SecurityLimits(
                maxDexTotalBytes = 2048,
                maxZipTotalUncompressedBytes = 1024
            ).validate()
        }
    }

    @Test
    fun `jadx thread count is bounded by config cpu and security limit`() {
        val limits = SecurityLimits(maxJadxThreads = 8).validate()

        assertEquals(4, limits.effectiveJadxThreads(4, 32))
        assertEquals(8, limits.effectiveJadxThreads(64, 32))
        assertEquals(1, limits.effectiveJadxThreads(null, 1))
    }

    @Test
    fun `legacy analysis limits are validated`() {
        assertThrows(IllegalArgumentException::class.java) {
            ArgumentConfig(apkPath = "app.apk", maxPointerAnalyzeTime = 0).validate()
        }
        assertThrows(IllegalArgumentException::class.java) {
            ArgumentConfig(apkPath = "app.apk", maxThread = 0).validate()
        }
        assertThrows(IllegalArgumentException::class.java) {
            ArgumentConfig(apkPath = "app.apk", maxPathLength = 0).validate()
        }
    }
}
