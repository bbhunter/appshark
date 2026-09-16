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

package net.bytedance.security.app.android

import net.bytedance.security.app.security.ScanLimitExceededException
import net.bytedance.security.app.security.ScanToolException
import net.bytedance.security.app.security.ScanWorkspace
import net.bytedance.security.app.security.SecurityLimits
import net.bytedance.security.app.security.SecurityTestFixtures.testLimits
import net.bytedance.security.app.security.SecurityTestFixtures.zipOf
import net.bytedance.security.app.util.Json
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeFalse
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit

internal class JadxRunnerTest {
    @Test
    fun `successful run publishes metadata and matching cache is reused`() {
        assumeUnix()
        withWorkspace { workspace ->
            val executions = workspace.root.resolve("executions")
            val executable = shellScript(
                workspace.root,
                """
                    printf x >> "$executions"
                    mkdir -p "${'$'}6/app/src/main/java"
                    printf 'class Test {}' > "${'$'}6/app/src/main/java/Test.java"
                """
            )
            val runner = JadxRunner()

            val first = runner.run(executable, workspace, limits(), 2, 5)
            val second = runner.run(executable, workspace, limits(), 2, 5)

            assertEquals(workspace.jadxOutput, first)
            assertEquals(first, second)
            assertEquals("x", Files.readString(executions))
            val metadata = Json.decodeFromString<JadxCacheMetadata>(
                Files.readString(workspace.jadxOutput.resolve("cache-metadata.json"))
            )
            assertTrue(metadata.complete)
            assertEquals(workspace.apkSha256, metadata.apkSha256)
        }
    }

    @Test
    fun `done marker alone is ignored`() {
        assumeUnix()
        withWorkspace { workspace ->
            Files.writeString(workspace.jadxOutput.resolve(".done"), "")
            val executable = shellScript(
                workspace.root,
                """
                    mkdir -p "${'$'}6/app/src/main/java"
                    printf 'class Test {}' > "${'$'}6/app/src/main/java/Test.java"
                """
            )

            JadxRunner().run(executable, workspace, limits(), 1, 5)

            assertTrue(Files.exists(workspace.jadxOutput.resolve("app/src/main/java/Test.java")))
            assertFalse(Files.exists(workspace.jadxOutput.resolve(".done")))
        }
    }

    @Test
    fun `non-zero exit fails closed without metadata`() {
        assumeUnix()
        withWorkspace { workspace ->
            val executable = shellScript(workspace.root, "exit 7")

            assertThrows(ScanToolException::class.java) {
                JadxRunner().run(executable, workspace, limits(), 1, 5)
            }

            assertFalse(Files.exists(workspace.jadxOutput.resolve("cache-metadata.json")))
        }
    }

    @Test
    fun `timeout terminates child process and leaves no metadata`() {
        assumeUnix()
        withWorkspace { workspace ->
            val executable = shellScript(
                workspace.root,
                """
                    sleep 60 &
                    printf '%s' "${'$'}!" > "${'$'}6/child.pid"
                    sleep 60
                """
            )

            assertThrows(ScanToolException::class.java) {
                JadxRunner().run(executable, workspace, limits(), 1, 1)
            }

            val childPid = Files.readString(workspace.jadxOutput.resolve("child.pid")).toLong()
            val child = ProcessHandle.of(childPid)
            if (child.isPresent) {
                child.get().onExit().get(3, TimeUnit.SECONDS)
            }
            assertFalse(ProcessHandle.of(childPid).map { it.isAlive }.orElse(false))
            assertFalse(Files.exists(workspace.jadxOutput.resolve("cache-metadata.json")))
        }
    }

    @Test
    fun `output byte limit terminates jadx`() {
        assumeUnix()
        withWorkspace { workspace ->
            val executable = shellScript(
                workspace.root,
                """
                    dd if=/dev/zero of="${'$'}6/large.bin" bs=1024 count=4 2>/dev/null
                    sleep 2
                """
            )
            val limits = limits().copy(maxJadxOutputBytes = 64).validate()

            assertThrows(ScanLimitExceededException::class.java) {
                JadxRunner().run(executable, workspace, limits, 1, 5)
            }

            assertFalse(Files.exists(workspace.jadxOutput.resolve("cache-metadata.json")))
        }
    }

    @Test
    fun `output file count limit is enforced`() {
        assumeUnix()
        withWorkspace { workspace ->
            val executable = shellScript(
                workspace.root,
                """
                    printf a > "${'$'}6/one"
                    printf b > "${'$'}6/two"
                    sleep 2
                """
            )
            val limits = limits().copy(maxJadxOutputFiles = 1).validate()

            assertThrows(ScanLimitExceededException::class.java) {
                JadxRunner().run(executable, workspace, limits, 1, 5)
            }
        }
    }

    @Test
    fun `metadata comparison binds apk tool version and arguments`() {
        val base = JadxCacheMetadata(
            apkSha256 = "apk",
            apkBytes = 10,
            appSharkVersion = "version",
            jadxIdentity = "tool",
            argumentDigest = "args",
            complete = true
        )

        assertTrue(JadxRunner.isReusable(base, base))
        assertFalse(JadxRunner.isReusable(base.copy(apkSha256 = "different"), base))
        assertFalse(JadxRunner.isReusable(base.copy(apkBytes = 11), base))
        assertFalse(JadxRunner.isReusable(base.copy(appSharkVersion = "other"), base))
        assertFalse(JadxRunner.isReusable(base.copy(jadxIdentity = "other"), base))
        assertFalse(JadxRunner.isReusable(base.copy(argumentDigest = "other"), base))
        assertFalse(JadxRunner.isReusable(base.copy(complete = false), base))
        assertNotEquals(
            JadxRunner.argumentDigest(1),
            JadxRunner.argumentDigest(2)
        )
    }

    private fun withWorkspace(block: (ScanWorkspace) -> Unit) {
        val out = Files.createTempDirectory("appshark-jadx-test")
        val workspace = ScanWorkspace.create(
            out,
            zipOf("classes.dex" to ByteArray(8)),
            limits()
        )
        try {
            block(workspace)
        } finally {
            workspace.close()
        }
    }

    private fun limits(): SecurityLimits = testLimits().copy(
        maxJadxThreads = 4,
        maxJadxOutputFiles = 100,
        maxJadxOutputBytes = 1024 * 1024
    ).validate()

    private fun shellScript(directory: Path, body: String): Path {
        val script = Files.createTempFile(directory, "fake-jadx-", ".sh")
        Files.writeString(
            script,
            """
                #!/bin/bash
                set -eu
                $body
            """.trimIndent()
        )
        assertTrue(script.toFile().setExecutable(true))
        return script
    }

    private fun assumeUnix() {
        assumeFalse(System.getProperty("os.name").startsWith("Windows"))
    }
}
