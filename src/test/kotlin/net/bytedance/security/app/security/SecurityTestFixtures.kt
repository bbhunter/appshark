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

import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

internal object SecurityTestFixtures {
    fun zipOf(vararg entries: Pair<String, ByteArray>): Path {
        val path = Files.createTempFile("appshark-test", ".apk")
        ZipOutputStream(Files.newOutputStream(path)).use { zip ->
            entries.forEach { (name, bytes) ->
                zip.putNextEntry(ZipEntry(name))
                zip.write(bytes)
                zip.closeEntry()
            }
        }
        return path
    }

    fun testLimits(
        maxApkBytes: Long = 16 * 1024,
        maxZipEntries: Int = 10,
        maxZipEntryUncompressedBytes: Long = 8 * 1024,
        maxZipTotalUncompressedBytes: Long = 16 * 1024,
        maxZipCompressionRatio: Long = 100,
        maxDexFiles: Int = 4,
        maxDexTotalBytes: Long = 8 * 1024,
    ): SecurityLimits = SecurityLimits(
        maxApkBytes = maxApkBytes,
        maxZipEntries = maxZipEntries,
        maxZipEntryUncompressedBytes = maxZipEntryUncompressedBytes,
        maxZipTotalUncompressedBytes = maxZipTotalUncompressedBytes,
        maxZipCompressionRatio = maxZipCompressionRatio,
        maxDexFiles = maxDexFiles,
        maxDexTotalBytes = maxDexTotalBytes,
    ).validate()
}
