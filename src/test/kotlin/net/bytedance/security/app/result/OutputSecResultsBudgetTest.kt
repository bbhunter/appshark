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

package net.bytedance.security.app.result

import kotlinx.serialization.Serializable
import net.bytedance.security.app.RuleDescription
import net.bytedance.security.app.result.model.AnySerializer
import net.bytedance.security.app.rules.IRule
import net.bytedance.security.app.security.ScanBudget
import net.bytedance.security.app.security.ScanLimitExceededException
import net.bytedance.security.app.security.ScanRuntime
import net.bytedance.security.app.security.ScanWorkspace
import net.bytedance.security.app.security.SecurityTestFixtures.testLimits
import net.bytedance.security.app.security.SecurityTestFixtures.zipOf
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.nio.file.Files

internal class OutputSecResultsBudgetTest {
    @Test
    fun `result insertion obeys the active scan budget`() {
        val limits = testLimits().copy(maxResultCount = 1).validate()
        val out = Files.createTempDirectory("appshark-results-budget")
        val workspace = ScanWorkspace.create(
            out,
            zipOf("classes.dex" to ByteArray(8)),
            limits
        )
        OutputSecResults.testClearVulnerabilityItems()
        ScanRuntime.install(ScanBudget(limits), workspace)

        try {
            OutputSecResults.addOneVulnerability(testVulnerability())
            assertThrows(ScanLimitExceededException::class.java) {
                OutputSecResults.addOneVulnerability(testVulnerability())
            }
        } finally {
            OutputSecResults.testClearVulnerabilityItems()
            ScanRuntime.clear()
            workspace.close()
        }
    }

    private fun testVulnerability(): VulnerabilityItem =
        VulnerabilityItem(
            object : IRule {
                override val mode: String = "test"
                override val desc: RuleDescription = RuleDescription(name = "test")
                override val name: String = "test"
            },
            "",
            object : IVulnerability {
                override fun toDetail(): Map<String, @Serializable(with = AnySerializer::class) Any> =
                    emptyMap()

                override val target: List<String> = emptyList()
                override val position: String = ""
            }
        )
}
