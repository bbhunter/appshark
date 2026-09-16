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

package net.bytedance.security.app

import net.bytedance.security.app.security.ScanDeadline
import net.bytedance.security.app.security.ScanLimitExceededException
import net.bytedance.security.app.security.ScanOutputException
import net.bytedance.security.app.security.ScanRuntime
import net.bytedance.security.app.security.ScanToolException
import net.bytedance.security.app.security.SecurityTestFixtures.zipOf
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

internal class StaticAnalyzeMainSecurityTest {
    private val previousConfig = cfg

    @AfterEach
    fun restoreGlobals() {
        ScanRuntime.clear()
        cfg = previousConfig
    }

    @Test
    fun `empty arguments display usage and succeed`() {
        assertEquals(0, runCli(emptyArray(), RecordingExecutor()))
    }

    @Test
    fun `invalid security limits return invalid input status`() {
        val fixture = fixture()
        val config = writeConfig(
            fixture,
            securityLimits = """"maxApkBytes": -1"""
        )

        assertEquals(2, runCli(arrayOf(config.toString()), RecordingExecutor()))
    }

    @Test
    fun `invalid apk prevents executor invocation`() {
        val fixture = fixture(apk = Files.writeString(
            Files.createTempFile("appshark-invalid", ".apk"),
            "not a zip"
        ))
        val executor = RecordingExecutor()

        val status = runCli(arrayOf(writeConfig(fixture).toString()), executor)

        assertEquals(2, status)
        assertEquals(0, executor.calls)
    }

    @Test
    fun `executor receives immutable snapshot and workspace is cleaned after success`() {
        val fixture = fixture()
        var receivedPath: Path? = null
        val executor = RecordingExecutor { config ->
            receivedPath = Path.of(config.apkPath)
            assertTrue(Files.isRegularFile(receivedPath))
            assertTrue(ScanRuntime.workspace().apkSnapshot == receivedPath)
        }

        val status = runCli(arrayOf(writeConfig(fixture).toString()), executor)

        assertEquals(0, status)
        assertEquals(1, executor.calls)
        assertNotEquals(fixture.apk.toAbsolutePath().normalize(), receivedPath)
        assertFalse(Files.exists(receivedPath))
        assertWorkspaceEmpty(fixture.out)
    }

    @Test
    fun `workspace is cleaned and tool failure is non-zero`() {
        val fixture = fixture()
        val executor = RecordingExecutor {
            throw ScanToolException("fixture tool failure")
        }

        val status = runCli(arrayOf(writeConfig(fixture).toString()), executor)

        assertEquals(4, status)
        assertWorkspaceEmpty(fixture.out)
    }

    @Test
    fun `typed failures map to stable status codes`() {
        val limitFixture = fixture()
        val outputFixture = fixture()

        assertEquals(
            3,
            runCli(arrayOf(writeConfig(limitFixture).toString()), RecordingExecutor {
                throw ScanLimitExceededException("limit")
            })
        )
        assertEquals(
            5,
            runCli(arrayOf(writeConfig(outputFixture).toString()), RecordingExecutor {
                throw ScanOutputException("output")
            })
        )
    }

    @Test
    fun `deadline invokes callback once`() {
        val calls = AtomicInteger()
        val fired = CountDownLatch(1)
        ScanDeadline.start(1) {
            calls.incrementAndGet()
            fired.countDown()
        }.use {
            assertTrue(fired.await(3, TimeUnit.SECONDS))
            Thread.sleep(100)
        }

        assertEquals(1, calls.get())
    }

    private fun fixture(
        apk: Path = zipOf(
            "AndroidManifest.xml" to byteArrayOf(1),
            "classes.dex" to ByteArray(8)
        )
    ): Fixture = Fixture(
        apk = apk,
        out = Files.createTempDirectory("appshark-cli-out"),
        root = Files.createTempDirectory("appshark-cli-config")
    )

    private fun writeConfig(
        fixture: Fixture,
        securityLimits: String = """"maxApkBytes": 4096"""
    ): Path {
        val config = fixture.root.resolve("config.json5")
        Files.writeString(
            config,
            """
                {
                  "apkPath": ${jsonString(fixture.apk.toString())},
                  "out": ${jsonString(fixture.out.toString())},
                  "configPath": ${jsonString(Path.of("config").toAbsolutePath().toString())},
                  "rulePath": ${jsonString(Path.of("config/rules").toAbsolutePath().toString())},
                  "securityLimits": {
                    $securityLimits
                  }
                }
            """.trimIndent()
        )
        return config
    }

    private fun assertWorkspaceEmpty(out: Path) {
        val workRoot = out.resolve(".appshark-work")
        if (!Files.exists(workRoot)) {
            return
        }
        Files.list(workRoot).use { entries ->
            assertEquals(0, entries.count())
        }
    }

    private fun jsonString(value: String): String =
        "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

    private data class Fixture(val apk: Path, val out: Path, val root: Path)

    private class RecordingExecutor(
        private val action: suspend (ArgumentConfig) -> Unit = {}
    ) : ScanExecutor {
        var calls = 0

        override suspend fun execute(config: ArgumentConfig) {
            calls++
            action(config)
        }
    }
}
