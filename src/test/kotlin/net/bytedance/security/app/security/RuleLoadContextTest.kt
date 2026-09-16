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

import kotlinx.coroutines.runBlocking
import net.bytedance.security.app.rules.RuleFactory
import net.bytedance.security.app.rules.Rules
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path

internal class RuleLoadContextTest {
    @Test
    fun `direct rule reference cycle is rejected`() {
        val root = Files.createTempDirectory("appshark-rule-cycle")
        val a = writeRule(root, "a.json", directRule("A", "a.json"))

        assertThrows(IllegalArgumentException::class.java) {
            RuleLoadContext(root, SecurityLimits()).loadTopLevel(listOf(a))
        }
    }

    @Test
    fun `indirect rule reference cycle is rejected`() {
        val root = Files.createTempDirectory("appshark-rule-cycle")
        val a = writeRule(root, "a.json", directRule("A", "b.json"))
        writeRule(root, "b.json", directRule("B", "c.json"))
        writeRule(root, "c.json", directRule("C", "a.json"))

        assertThrows(IllegalArgumentException::class.java) {
            RuleLoadContext(root, SecurityLimits()).loadTopLevel(listOf(a))
        }
    }

    @Test
    fun `rule reference depth is bounded`() {
        val root = Files.createTempDirectory("appshark-rule-depth")
        val a = writeRule(root, "a.json", directRule("A", "b.json"))
        writeRule(root, "b.json", directRule("B", "c.json"))
        writeRule(root, "c.json", leafRule("C"))
        val limits = SecurityLimits(maxRuleReferenceDepth = 2).validate()

        assertThrows(IllegalArgumentException::class.java) {
            RuleLoadContext(root, limits).loadTopLevel(listOf(a))
        }
    }

    @Test
    fun `rule file reference and byte totals are bounded`() {
        val root = Files.createTempDirectory("appshark-rule-budget")
        val a = writeRule(
            root,
            "a.json",
            """
            {
              "A": {
                "DirectMode": true,
                "traceDepth": 8,
                "desc": {"name": "A"},
                "sourceRuleObj": [
                  {"ruleFile": "b.json"},
                  {"ruleFile": "c.json"}
                ]
              }
            }
            """.trimIndent()
        )
        writeRule(root, "b.json", leafRule("B"))
        writeRule(root, "c.json", leafRule("C"))

        assertThrows(IllegalArgumentException::class.java) {
            RuleLoadContext(
                root,
                SecurityLimits(maxRuleFiles = 1).validate()
            ).loadTopLevel(listOf(a))
        }
        assertThrows(IllegalArgumentException::class.java) {
            RuleLoadContext(
                root,
                SecurityLimits(maxRuleReferences = 1).validate()
            ).loadTopLevel(listOf(a))
        }
        assertThrows(IllegalArgumentException::class.java) {
            RuleLoadContext(
                root,
                SecurityLimits(maxRuleTotalBytes = 16).validate()
            ).loadTopLevel(listOf(a))
        }
    }

    @Test
    fun `repeated valid references parse one file once`() {
        val root = Files.createTempDirectory("appshark-rule-cache")
        val a = writeRule(
            root,
            "a.json",
            """
            {
              "A": {
                "DirectMode": true,
                "traceDepth": 8,
                "desc": {"name": "A"},
                "sourceRuleObj": [
                  {"ruleFile": "shared.json"},
                  {"ruleFile": "shared.json"}
                ]
              }
            }
            """.trimIndent()
        )
        writeRule(root, "shared.json", leafRule("Shared"))
        val context = RuleLoadContext(root, SecurityLimits())

        context.loadTopLevel(listOf(a))

        assertEquals(2, context.ruleDigests().size)
    }

    @Test
    fun `oversized strings and collections are rejected`() {
        val root = Files.createTempDirectory("appshark-rule-structure")
        val longString = writeRule(root, "long.json", leafRule("12345"))
        val largeArray = writeRule(
            root,
            "array.json",
            """
            {
              "A": {
                "DirectMode": true,
                "desc": {"name": "A"},
                "sourceRuleObj": [
                  {"ruleFile": "leaf.json"},
                  {"ruleFile": "leaf.json"}
                ]
              }
            }
            """.trimIndent()
        )
        writeRule(root, "leaf.json", leafRule("Leaf"))

        assertThrows(IllegalArgumentException::class.java) {
            RuleLoadContext(
                root,
                SecurityLimits(maxRuleStringChars = 4).validate()
            ).loadTopLevel(listOf(longString))
        }
        assertThrows(IllegalArgumentException::class.java) {
            RuleLoadContext(
                root,
                SecurityLimits(maxRuleCollectionEntries = 1).validate()
            ).loadTopLevel(listOf(largeArray))
        }
    }

    @Test
    fun `duplicate rule names across files are rejected`() {
        val root = Files.createTempDirectory("appshark-rule-duplicate")
        val first = writeRule(root, "a.json", leafRule("Duplicate"))
        val second = writeRule(root, "b.json", leafRule("Duplicate"))

        assertThrows(IllegalArgumentException::class.java) {
            RuleLoadContext(root, SecurityLimits()).loadTopLevel(listOf(first, second))
        }
    }

    @Test
    fun `valid nested direct mode rule still loads`() {
        val root = Files.createTempDirectory("appshark-rule-valid")
        val top = writeRule(root, "top.json", directRule("Top", "leaf.json"))
        writeRule(
            root,
            "leaf.json",
            """
            {
              "Leaf": {
                "DirectMode": true,
                "traceDepth": 8,
                "desc": {"name": "Leaf"},
                "source": {"Return": ["<a.A: java.lang.String source()>"]}
              }
            }
            """.trimIndent()
        )
        val context = RuleLoadContext(root, SecurityLimits())
        val rules = Rules(listOf(top.toString()), RuleFactory(), context)

        runBlocking {
            rules.loadRules()
        }

        assertEquals(1, rules.allRules.size)
        assertEquals("Top", rules.allRules.single().name)
        assertEquals(2, rules.ruleDigests().size)
        assertTrue(rules.ruleDigests().keys.all { !Path.of(it).isAbsolute })
    }

    private fun writeRule(root: Path, name: String, content: String): Path =
        Files.writeString(root.resolve(name), content)

    private fun directRule(name: String, reference: String): String =
        """
        {
          "$name": {
            "DirectMode": true,
            "traceDepth": 8,
            "desc": {"name": "$name"},
            "sourceRuleObj": [{"ruleFile": "$reference"}]
          }
        }
        """.trimIndent()

    private fun leafRule(name: String): String =
        """
        {
          "$name": {
            "DirectMode": true,
            "traceDepth": 8,
            "desc": {"name": "$name"},
            "source": {"Return": []}
          }
        }
        """.trimIndent()
}
