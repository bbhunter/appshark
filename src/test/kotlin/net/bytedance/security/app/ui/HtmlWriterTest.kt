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


package net.bytedance.security.app.ui

import kotlinx.html.TagConsumer
import net.bytedance.security.app.ArgumentConfig
import net.bytedance.security.app.RuleData
import net.bytedance.security.app.RuleDescription
import net.bytedance.security.app.cfg
import net.bytedance.security.app.util.Json
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

val data = """
    {
    //it's ok to have a comment
    "unZipSlipDirectModeMode": {
      "traceDepth": 8,
      "desc": {
        "name": "unZipSlip" 
      },
      "entry": {
        "methods": [
          "<net.bytedance.security.app.ruleprocessor.testdata.ZipSlip: void UnZipFolder(java.lang.String,java.lang.String)>"
        ]
      },
      "source": {
        "Return": [
          "<java.util.zip.ZipEntry: java.lang.String getName()>"
        ]
      },
      "sink": {
        "<java.io.FileWriter: * <init>(*)>": {
          "TaintCheck": [
            "p*"
          ]
        },
        "<java.io.FileOutputStream: * <init>(*)>": {
          "TaintCheck": [
            "p*"
          ]
        }
      }
    }
  }
""".trimIndent()

internal class HtmlWriterTest {
    @Test
    fun `malicious report text is escaped`() {
        val html = renderDescription(
            RuleDescription(
                name = """<img src=x onerror=alert(1)>""",
                detail = """</code><script>alert(1)</script>"""
            )
        )

        assertFalse(html.contains("<script>alert(1)</script>"))
        assertFalse(html.contains("<img src=x onerror=alert(1)>"))
        assertTrue(html.contains("&lt;script&gt;"), html)
    }

    @Test
    fun `dangerous wiki and apk schemes are not links`() {
        val previousConfig = cfg
        cfg = ArgumentConfig(
            apkPath = "app.apk",
            deobfApk = "data:text/html,<script>alert(2)</script>"
        )

        try {
            val html = renderDescription(
                RuleDescription(name = "rule", wiki = "javascript:alert(1)")
            )

            assertFalse(html.contains("""href="javascript:"""))
            assertFalse(html.contains("""href="data:"""))
            assertTrue(html.contains("javascript:alert(1)"), html)
            assertTrue(html.contains("data:text/html"))
        } finally {
            cfg = previousConfig
        }
    }

    @Test
    fun `http links are allowed with opener isolation`() {
        val html = renderDescription(
            RuleDescription(name = "rule", wiki = "https://example.com/rule")
        )

        assertTrue(html.contains("""href="https://example.com/rule""""), html)
        assertTrue(html.contains("""rel="noopener noreferrer""""))
        assertTrue(html.contains("""target="_blank""""))
    }

    @Test
    fun `report is self contained and declares restrictive csp`() {
        val html = HtmlWriter(RuleDescription(name = "rule")).generateHtml()

        assertFalse(html.contains("cdnjs.cloudflare.com"))
        assertFalse(html.contains("<script"))
        assertTrue(html.contains("Content-Security-Policy"))
        assertTrue(
            html.contains("default-src &#39;none&#39;") ||
                html.contains("default-src 'none'")
        )
    }

    @Test
    fun `html output name is a single safe path component`() {
        val writer = HtmlWriter(
            RuleDescription(name = "controlled/../../escaped\\report")
        )

        assertFalse(writer.htmlName.contains('/'))
        assertFalse(writer.htmlName.contains('\\'))
        assertFalse(writer.htmlName.contains(".."))
        assertTrue(writer.htmlName.endsWith(".html"))
    }

    @Test
    fun testHtml() {
        val s = data
        val rules: Map<String, RuleData> = Json.decodeFromString(s)
        val desc = rules["unZipSlipDirectModeMode"]!!.desc
        val hw = HtmlWriter(desc)
        val s2 = hw.generateHtml()
        println(s2)
    }

    private fun renderDescription(desc: RuleDescription): String =
        object : HtmlWriter(desc) {
            override fun genContent(tag: TagConsumer<*>) {
                genVulInfo(tag)
            }
        }.generateHtml()
}
