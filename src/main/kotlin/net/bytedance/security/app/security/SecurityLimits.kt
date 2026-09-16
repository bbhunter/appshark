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

import kotlinx.serialization.Serializable

private const val MIB = 1024L * 1024
private const val GIB = 1024L * MIB

@Serializable
data class SecurityLimits(
    val maxApkBytes: Long = 2L * GIB,
    val maxZipEntries: Int = 200_000,
    val maxZipEntryUncompressedBytes: Long = 1L * GIB,
    val maxZipTotalUncompressedBytes: Long = 8L * GIB,
    val maxZipCompressionRatio: Long = 1_000,
    val maxZipEntryNameChars: Int = 4_096,
    val maxDexFiles: Int = 256,
    val maxDexTotalBytes: Long = 4L * GIB,
    val maxRuleFiles: Int = 4_096,
    val maxRuleTotalBytes: Long = 64L * MIB,
    val maxRuleReferenceDepth: Int = 16,
    val maxRuleReferences: Int = 8_192,
    val maxRuleStringChars: Int = 65_536,
    val maxRuleCollectionEntries: Int = 100_000,
    val maxTotalAnalyzers: Int = 100_000,
    val maxScanSeconds: Long = 14_400,
    val maxJadxThreads: Int = 16,
    val maxJadxOutputFiles: Long = 1_000_000,
    val maxJadxOutputBytes: Long = 20L * GIB,
    val maxResultCount: Int = 100_000,
    val maxReportFiles: Int = 100_000,
    val maxReportBytes: Long = 2L * GIB,
    val maxLogBytes: Long = 256L * MIB,
    val maxLogLineChars: Int = 16_384,
) {
    fun validate(): SecurityLimits {
        require(maxApkBytes > 0) { "maxApkBytes must be positive" }
        require(maxZipEntries > 0) { "maxZipEntries must be positive" }
        require(maxZipEntryUncompressedBytes > 0) {
            "maxZipEntryUncompressedBytes must be positive"
        }
        require(maxZipTotalUncompressedBytes > 0) {
            "maxZipTotalUncompressedBytes must be positive"
        }
        require(maxZipCompressionRatio > 0) { "maxZipCompressionRatio must be positive" }
        require(maxZipEntryNameChars > 0) { "maxZipEntryNameChars must be positive" }
        require(maxDexFiles > 0) { "maxDexFiles must be positive" }
        require(maxDexTotalBytes > 0) { "maxDexTotalBytes must be positive" }
        require(maxRuleFiles > 0) { "maxRuleFiles must be positive" }
        require(maxRuleTotalBytes > 0) { "maxRuleTotalBytes must be positive" }
        require(maxRuleReferenceDepth > 0) { "maxRuleReferenceDepth must be positive" }
        require(maxRuleReferences > 0) { "maxRuleReferences must be positive" }
        require(maxRuleStringChars > 0) { "maxRuleStringChars must be positive" }
        require(maxRuleCollectionEntries > 0) {
            "maxRuleCollectionEntries must be positive"
        }
        require(maxTotalAnalyzers > 0) { "maxTotalAnalyzers must be positive" }
        require(maxScanSeconds > 0) { "maxScanSeconds must be positive" }
        require(maxJadxThreads > 0) { "maxJadxThreads must be positive" }
        require(maxJadxOutputFiles > 0) { "maxJadxOutputFiles must be positive" }
        require(maxJadxOutputBytes > 0) { "maxJadxOutputBytes must be positive" }
        require(maxResultCount > 0) { "maxResultCount must be positive" }
        require(maxReportFiles > 0) { "maxReportFiles must be positive" }
        require(maxReportBytes > 0) { "maxReportBytes must be positive" }
        require(maxLogBytes > 0) { "maxLogBytes must be positive" }
        require(maxLogLineChars > 0) { "maxLogLineChars must be positive" }

        require(maxZipEntryUncompressedBytes <= maxZipTotalUncompressedBytes) {
            "maxZipEntryUncompressedBytes must not exceed maxZipTotalUncompressedBytes"
        }
        require(maxDexTotalBytes <= maxZipTotalUncompressedBytes) {
            "maxDexTotalBytes must not exceed maxZipTotalUncompressedBytes"
        }
        Math.multiplyExact(maxScanSeconds, 1000L)
        return this
    }

    fun effectiveJadxThreads(configuredThreads: Int?, processors: Int): Int {
        val availableProcessors = processors.coerceAtLeast(1)
        return minOf(
            maxJadxThreads,
            configuredThreads ?: availableProcessors,
            availableProcessors
        ).coerceAtLeast(1)
    }
}
