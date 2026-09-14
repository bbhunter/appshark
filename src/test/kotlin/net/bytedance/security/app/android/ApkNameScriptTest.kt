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

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path

internal class ApkNameScriptTest {
    @Test
    fun `apk path with spaces and glob characters remains one argument`() {
        val temp = Files.createTempDirectory("appshark-apk-name")
        val argumentLog = temp.resolve("aapt-arguments.txt")
        val fakeAapt = temp.resolve("aapt")
        Files.writeString(
            fakeAapt,
            """
                #!/bin/bash
                printf '%s\n' "${'$'}@" > "${'$'}ARGUMENT_LOG"
                printf "application-label-zh-CN:'测试应用'\n"
            """.trimIndent()
        )
        fakeAapt.toFile().setExecutable(true)
        val apkPath = temp.resolve("app shark/[sample] app.apk").toString()
        val script = Path.of(
            System.getProperty("user.dir"),
            "config",
            "tools",
            "ApkName.sh"
        )
        val process = ProcessBuilder(script.toString(), apkPath)
            .redirectErrorStream(true)
            .apply {
                environment()["ARGUMENT_LOG"] = argumentLog.toString()
                environment()["PATH"] = "$temp:${environment()["PATH"]}"
            }
            .start()

        val output = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()

        assertEquals(0, exitCode, output)
        assertEquals("dump\nbadging\n$apkPath\n", Files.readString(argumentLog))
        assertEquals("测试应用", output.trim())
    }
}
