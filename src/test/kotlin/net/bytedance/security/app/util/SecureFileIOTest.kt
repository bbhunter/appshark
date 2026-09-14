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

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeFalse
import org.junit.jupiter.api.Test
import java.nio.file.FileAlreadyExistsException
import java.nio.file.Files

internal class SecureFileIOTest {
    @Test
    fun `output names never contain path separators or dot segments`() {
        val name = SecureFileIO.safeOutputFileName(
            "controlled/../../escaped\\report\u0000.html"
        )

        assertFalse(name.contains('/'))
        assertFalse(name.contains('\\'))
        assertFalse(name.contains(".."))
        assertTrue(name.endsWith(".html"))
    }

    @Test
    fun `long normalized names remain deterministic and collision resistant`() {
        val first = SecureFileIO.safeOutputFileName("a".repeat(300) + "x.html")
        val second = SecureFileIO.safeOutputFileName("a".repeat(300) + "y.html")

        assertTrue(first.length <= 160)
        assertEquals(first, SecureFileIO.safeOutputFileName("a".repeat(300) + "x.html"))
        assertNotEquals(first, second)
    }

    @Test
    fun `contained writer rejects traversal`() {
        val root = Files.createTempDirectory("appshark-report")

        assertThrows(IllegalArgumentException::class.java) {
            SecureFileIO.writeContainedFile(root, "../escaped.html", byteArrayOf(1))
        }
    }

    @Test
    fun `contained writer rejects symbolic link targets`() {
        assumeFalse(System.getProperty("os.name").startsWith("Windows"))
        val root = Files.createTempDirectory("appshark-report")
        val outside = Files.createTempFile("outside", ".html")
        Files.createSymbolicLink(root.resolve("report.html"), outside)

        assertThrows(FileAlreadyExistsException::class.java) {
            SecureFileIO.writeContainedFile(root, "report.html", "safe".toByteArray())
        }
        assertEquals(0, Files.size(outside))
    }

    @Test
    fun `contained writer writes a new regular file inside the directory`() {
        val root = Files.createTempDirectory("appshark-report")

        val written = SecureFileIO.writeContainedFile(root, "report.html", "safe".toByteArray())

        assertEquals(root.toRealPath(), written.parent)
        assertEquals("safe", String(Files.readAllBytes(written)))
    }

    @Test
    fun `rule resolver rejects parent traversal`() {
        val root = Files.createTempDirectory("rules")

        assertThrows(IllegalArgumentException::class.java) {
            SecureFileIO.resolveRuleFile(root, "../outside.json")
        }
    }

    @Test
    fun `rule resolver rejects absolute and non-json paths`() {
        val root = Files.createTempDirectory("rules")

        assertThrows(IllegalArgumentException::class.java) {
            SecureFileIO.resolveRuleFile(root, root.resolve("rule.json").toString())
        }
        assertThrows(IllegalArgumentException::class.java) {
            SecureFileIO.resolveRuleFile(root, "rule.txt")
        }
    }

    @Test
    fun `rule resolver rejects symbolic link escape`() {
        assumeFalse(System.getProperty("os.name").startsWith("Windows"))
        val root = Files.createTempDirectory("rules")
        val outside = Files.createTempFile("outside-rule", ".json")
        Files.createSymbolicLink(root.resolve("linked.json"), outside)

        assertThrows(IllegalArgumentException::class.java) {
            SecureFileIO.resolveRuleFile(root, "linked.json")
        }
    }

    @Test
    fun `rule resolver accepts nested json5 file inside root`() {
        val root = Files.createTempDirectory("rules")
        val nested = Files.createDirectories(root.resolve("nested")).resolve("common.json5")
        Files.writeString(nested, "{}")

        val resolved = SecureFileIO.resolveRuleFile(root, "nested/common.json5")

        assertEquals(nested.toRealPath(), resolved)
    }

    @Test
    fun `bounded reader rejects oversized files`() {
        val file = Files.createTempFile("large-rule", ".json")
        Files.write(file, ByteArray(33) { 'a'.code.toByte() })

        assertThrows(IllegalArgumentException::class.java) {
            SecureFileIO.readUtf8(file, 32, "rule file")
        }
    }

    @Test
    fun `bounded reader accepts exactly the configured byte limit`() {
        val file = Files.createTempFile("bounded-rule", ".json")
        val content = "规则".toByteArray(Charsets.UTF_8)
        Files.write(file, content)

        assertEquals(
            "规则",
            SecureFileIO.readUtf8(file, content.size.toLong(), "rule file")
        )
    }
}
