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


package net.bytedance.security.app.rules

import kotlinx.coroutines.runBlocking
import net.bytedance.security.app.AnalyzeStepByStep
import net.bytedance.security.app.ArgumentConfig
import net.bytedance.security.app.RuleData
import net.bytedance.security.app.RuleDescription
import net.bytedance.security.app.RuleObjBody
import net.bytedance.security.app.cfg
import net.bytedance.security.app.getConfig
import net.bytedance.security.app.security.RuleLoadContext
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Assumptions.assumeFalse
import java.io.File
import java.nio.file.Files
import java.nio.file.Paths

internal class RulesTest {

    fun createDefaultRules(): Rules {
        val rules = Rules(
            listOf(
                "${getConfig().rulePath}/unZipSlip.json",
            ),
            RuleFactory(),
            RuleLoadContext(Paths.get(getConfig().rulePath), getConfig().securityLimits)
        )
        runBlocking {
            rules.loadRules()
        }
        return rules
    }

    @Test
    fun constStringPatterns() {
        val rules = createDefaultRules()
        println(rules.constStringPatterns().toSortedSet().toList())
    }

    @Test
    fun newInstances() {
        val rules = createDefaultRules()
        println(rules.newInstances().toSortedSet().toList())
    }

    @Test
    fun fields() {
        val rules = createDefaultRules()
        println(rules.fields().toSortedSet().toList())
    }


    @Test
    fun testAllRules() {
        val rules = Rules(
            getAllRules(),
            RuleFactory(),
            RuleLoadContext(Paths.get(getConfig().rulePath), getConfig().securityLimits)
        )
        runBlocking {
            rules.loadRules()
        }
        println("const strings=${rules.constStringPatterns().toSortedSet().toList()}")
        println("fields=${rules.fields().toSortedSet().toList()}")
        println("new instances=${rules.newInstances().toSortedSet().toList()}")
    }

    @Test
    fun testParseSdkVersion() {
        assertEquals(
            (9..50).toList(),
            Rules.parseSdkVersion("")
        )
        assertEquals(
            (9..50).toList(),
            Rules.parseSdkVersion(":")
        )
        assertEquals(
            (9..10).toList() + listOf(15) + (25..30).toList() + (45..50).toList(),
            Rules.parseSdkVersion(":10, 15, 25:30, 45:")
        )
    }

    @Test
    fun `explicit rule list cannot escape configured rule root`() {
        val previousConfig = cfg
        val parent = Files.createTempDirectory("appshark-rules")
        val root = Files.createDirectory(parent.resolve("rules"))
        Files.writeString(parent.resolve("outside.json"), "{}")
        cfg = ArgumentConfig(apkPath = "app.apk", rulePath = root.toString())

        try {
            assertThrows(IllegalArgumentException::class.java) {
                runBlocking {
                    AnalyzeStepByStep().loadRules("../outside.json", -1, -1)
                }
            }
        } finally {
            cfg = previousConfig
        }
    }

    @Test
    fun `explicit nested rule file inside configured root loads`() {
        val previousConfig = cfg
        val root = Files.createTempDirectory("appshark-rules")
        val nested = Files.createDirectories(root.resolve("nested"))
        Files.writeString(nested.resolve("empty.json5"), "{}")
        cfg = ArgumentConfig(apkPath = "app.apk", rulePath = root.toString())

        try {
            val rules = runBlocking {
                AnalyzeStepByStep().loadRules("nested/empty.json5", -1, -1)
            }
            assertTrue(rules.allRules.isEmpty())
        } finally {
            cfg = previousConfig
        }
    }

    @Test
    fun `automatic rule discovery rejects symbolic link files`() {
        assumeFalse(System.getProperty("os.name").startsWith("Windows"))
        val previousConfig = cfg
        val parent = Files.createTempDirectory("appshark-rules")
        val root = Files.createDirectory(parent.resolve("rules"))
        val outside = Files.writeString(parent.resolve("outside.json"), "{}")
        Files.createSymbolicLink(root.resolve("linked.json"), outside)
        cfg = ArgumentConfig(apkPath = "app.apk", rulePath = root.toString())

        try {
            assertThrows(IllegalArgumentException::class.java) {
                runBlocking {
                    AnalyzeStepByStep().loadRules("", -1, -1)
                }
            }
        } finally {
            cfg = previousConfig
        }
    }

    @Test
    fun `direct mode nested rule reference cannot escape configured rule root`() {
        val previousConfig = cfg
        val parent = Files.createTempDirectory("appshark-rules")
        val root = Files.createDirectory(parent.resolve("rules"))
        Files.writeString(parent.resolve("outside.json"), "{}")
        cfg = ArgumentConfig(apkPath = "app.apk", rulePath = root.toString())

        try {
            val rule = DirectModeRule(
                "testRule",
                RuleData(
                    desc = RuleDescription(name = "testRule"),
                    sourceRuleObj = listOf(RuleObjBody(ruleFile = "../outside.json")),
                    traceDepth = 8
                ),
                RuleLoadContext(root, getConfig().securityLimits)
            )
            assertThrows(IllegalArgumentException::class.java) {
                runBlocking {
                    rule.initIfNeeded()
                }
            }
        } finally {
            cfg = previousConfig
        }
    }

    companion object {
        fun getAllRules(): List<String> {
            val rules = ArrayList<String>()
            File(getConfig().rulePath).walk().forEach {
//            println(it.absolutePath)
                if (it.absolutePath.endsWith(".json") || it.absolutePath.endsWith(".json5")) {
                    rules.add(it.absolutePath)
                }
            }
            println(rules)
            return rules
        }

        fun createDefaultRules(): Rules {
            val rules = Rules(
                getAllRules(),
                RuleFactory(),
                RuleLoadContext(Paths.get(getConfig().rulePath), getConfig().securityLimits)
            )
            runBlocking {
                rules.loadRules()
            }
            return rules
        }
    }
}
