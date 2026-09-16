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
import net.bytedance.security.app.util.SecureFileIO
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeFalse
import org.junit.jupiter.api.Test
import java.nio.file.Files

internal class ScanWorkspaceTest {
    @Test
    fun `workspace snapshots apk and binds digest`() {
        val out = Files.createTempDirectory("appshark-out")
        val source = zipOf("classes.dex" to ByteArray(64) { it.toByte() })

        ScanWorkspace.create(out, source, testLimits()).use { workspace ->
            val snapshotBeforeMutation = Files.readAllBytes(workspace.apkSnapshot)
            Files.write(source, byteArrayOf(9, 9, 9))

            assertArrayEquals(snapshotBeforeMutation, Files.readAllBytes(workspace.apkSnapshot))
            assertFalse(snapshotBeforeMutation.contentEquals(Files.readAllBytes(source)))
            assertTrue(workspace.apkSnapshot.startsWith(out.resolve(".appshark-work")))
            assertEquals(
                SecureFileIO.sha256(workspace.apkSnapshot, testLimits().maxApkBytes),
                workspace.apkSha256
            )
            assertTrue(Files.isDirectory(workspace.jadxOutput))
        }
    }

    @Test
    fun `task roots are unique and removed on close`() {
        val out = Files.createTempDirectory("appshark-out")
        val source = zipOf("classes.dex" to ByteArray(16))
        val first = ScanWorkspace.create(out, source, testLimits())
        val second = ScanWorkspace.create(out, source, testLimits())
        val firstRoot = first.root
        val secondRoot = second.root

        assertNotEquals(firstRoot, secondRoot)
        assertTrue(Files.exists(firstRoot.resolve(".appshark-owner")))
        assertTrue(Files.exists(secondRoot.resolve(".appshark-owner")))

        first.close()
        second.close()

        assertFalse(Files.exists(firstRoot))
        assertFalse(Files.exists(secondRoot))
    }

    @Test
    fun `symbolic link output root is rejected`() {
        assumeFalse(System.getProperty("os.name").startsWith("Windows"))
        val realOut = Files.createTempDirectory("appshark-real-out")
        val link = realOut.parent.resolve("appshark-linked-out-${realOut.fileName}")
        Files.createSymbolicLink(link, realOut)
        val source = zipOf("classes.dex" to ByteArray(16))

        assertThrows(IllegalArgumentException::class.java) {
            ScanWorkspace.create(link, source, testLimits())
        }
    }

    @Test
    fun `altered ownership marker prevents cleanup`() {
        val out = Files.createTempDirectory("appshark-out")
        val source = zipOf("classes.dex" to ByteArray(16))
        val workspace = ScanWorkspace.create(out, source, testLimits())
        Files.writeString(workspace.root.resolve(".appshark-owner"), "attacker")

        assertThrows(IllegalArgumentException::class.java) {
            workspace.close()
        }
        assertTrue(Files.exists(workspace.root))
    }

    @Test
    fun `cleanup deletes a child symlink without deleting its target`() {
        assumeFalse(System.getProperty("os.name").startsWith("Windows"))
        val out = Files.createTempDirectory("appshark-out")
        val source = zipOf("classes.dex" to ByteArray(16))
        val outside = Files.createTempFile("appshark-outside", ".txt")
        Files.writeString(outside, "keep")
        val workspace = ScanWorkspace.create(out, source, testLimits())
        Files.createSymbolicLink(workspace.root.resolve("outside-link"), outside)
        val root = workspace.root

        workspace.close()

        assertFalse(Files.exists(root))
        assertEquals("keep", Files.readString(outside))
    }
}
