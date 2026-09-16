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

import net.bytedance.security.app.Log.logInfo
import net.bytedance.security.app.security.ScanBudget
import net.bytedance.security.app.security.ScanRuntime
import net.bytedance.security.app.security.ScanWorkspace
import net.bytedance.security.app.security.SecurityTestFixtures.testLimits
import net.bytedance.security.app.security.SecurityTestFixtures.zipOf
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files

internal class LogTest {
    @Test
    fun `active scan logging escapes untrusted control characters`() {
        val limits = testLimits().copy(
            maxLogLineChars = 64,
            maxLogBytes = 1024
        ).validate()
        val out = Files.createTempDirectory("appshark-log-test")
        val workspace = ScanWorkspace.create(
            out,
            zipOf("classes.dex" to ByteArray(8)),
            limits
        )
        val originalOut = System.out
        val captured = ByteArrayOutputStream()

        ScanRuntime.install(ScanBudget(limits), workspace)
        try {
            System.setOut(PrintStream(captured, true, StandardCharsets.UTF_8.name()))
            logInfo("unsafe\n\u001Btext")
        } finally {
            System.setOut(originalOut)
            ScanRuntime.clear()
            workspace.close()
        }

        val output = captured.toString(StandardCharsets.UTF_8.name())
        assertTrue(output.contains("unsafe\\u000A\\u001Btext"))
        assertFalse(output.contains("unsafe\n"))
    }
}
