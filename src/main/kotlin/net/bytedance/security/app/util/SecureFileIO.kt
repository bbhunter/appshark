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

package net.bytedance.security.app.util

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.security.MessageDigest

object SecureFileIO {
    private const val MAX_REPORT_STEM_LENGTH = 120

    fun safeOutputFileName(fileName: String): String {
        val extensionIndex = fileName.lastIndexOf('.')
        val extension = if (extensionIndex > 0) {
            fileName.substring(extensionIndex).takeIf {
                it.matches(Regex("""\.[A-Za-z0-9]+"""))
            } ?: ""
        } else {
            ""
        }
        val originalStem = if (extension.isEmpty()) {
            fileName
        } else {
            fileName.dropLast(extension.length)
        }
        val normalized = originalStem
            .map { ch ->
                when {
                    ch.isLetterOrDigit() -> ch
                    ch == '.' || ch == '_' || ch == '-' -> ch
                    else -> '_'
                }
            }
            .joinToString("")
            .replace(Regex("""\.+"""), ".")
            .trim('.', '_')

        val stem = normalized.ifBlank { "report" }
        if (stem.length <= MAX_REPORT_STEM_LENGTH) {
            return "$stem$extension"
        }

        val digest = sha256(fileName).take(12)
        return "${stem.take(MAX_REPORT_STEM_LENGTH - digest.length - 1)}-$digest$extension"
    }

    fun writeContainedFile(directory: Path, fileName: String, bytes: ByteArray): Path {
        require(fileName.isNotEmpty()) { "File name must not be empty" }

        Files.createDirectories(directory)
        val noFollowDirectory = directory.toRealPath(LinkOption.NOFOLLOW_LINKS)
        require(!Files.isSymbolicLink(noFollowDirectory)) {
            "Output directory must not be a symbolic link: $directory"
        }
        val realDirectory = directory.toRealPath()

        val relativeName = Path.of(fileName)
        require(!relativeName.isAbsolute && relativeName.nameCount == 1) {
            "File name must not contain a path: $fileName"
        }

        val target = realDirectory.resolve(relativeName).normalize()
        require(target.parent == realDirectory) {
            "File must remain inside output directory: $fileName"
        }

        return Files.write(
            target,
            bytes,
            StandardOpenOption.CREATE_NEW,
            StandardOpenOption.WRITE,
            LinkOption.NOFOLLOW_LINKS
        )
    }

    private fun sha256(value: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(value.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { byte ->
                (byte.toInt() and 0xff).toString(16).padStart(2, '0')
            }
}
