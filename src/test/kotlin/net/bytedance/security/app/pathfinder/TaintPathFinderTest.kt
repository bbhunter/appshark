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


package net.bytedance.security.app.pathfinder

import kotlinx.coroutines.runBlocking
import net.bytedance.security.app.ArgumentConfig
import net.bytedance.security.app.cfg
import net.bytedance.security.app.result.OutputSecResults
import net.bytedance.security.app.ruleprocessor.DirectModeProcessor
import net.bytedance.security.app.ruleprocessor.RuleProcessorFactory
import net.bytedance.security.app.ruleprocessor.RuleProcessorFactoryTest
import net.bytedance.security.app.rules.TaintFlowRule
import net.bytedance.security.app.security.ScanBudget
import net.bytedance.security.app.security.ScanRuntime
import net.bytedance.security.app.security.ScanWorkspace
import net.bytedance.security.app.security.SecurityTestFixtures.testLimits
import net.bytedance.security.app.security.SecurityTestFixtures.zipOf
import net.bytedance.security.app.taintflow.TwoStagePointerAnalyzeTest.Companion.createDefaultTwoStagePointerAnalyze
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path
import test.SootHelper
import test.TestHelper

internal class TaintPathFinderTest {
    private val previousConfig = cfg
    private lateinit var workspace: ScanWorkspace

    init {
        SootHelper.initSoot(
            "TaintPathFinderTest",
            listOf("${TestHelper.getTestClassSourceFileDirectory(this.javaClass.name)}/testdata")
        )
    }

    @BeforeEach
    fun installScanRuntime() {
        val limits = testLimits()
        val out = Files.createTempDirectory("appshark-taint-path")
        cfg = ArgumentConfig(
            apkPath = "fixture.apk",
            outPath = out.toString(),
            configPath = Path.of("config").toAbsolutePath().toString(),
            rulePath = Path.of("config/rules").toAbsolutePath().toString(),
            securityLimits = limits
        )
        workspace = ScanWorkspace.create(
            out,
            zipOf("classes.dex" to ByteArray(8)),
            limits
        )
        ScanRuntime.install(ScanBudget(limits), workspace)
    }

    @AfterEach
    fun clearScanRuntime() {
        OutputSecResults.testClearVulnerabilityItems()
        ScanRuntime.clear()
        workspace.close()
        cfg = previousConfig
    }


    fun createTwoStagePointerAnalyzerFromRule(ruleFileName: String): TaintPathFinder {
        val rules = TestHelper.rulesFromFile(
            "${TestHelper.getTestClassSourceFileDirectory(this.javaClass.name)}/testdata/$ruleFileName"
        )
        val finder: TaintPathFinder
        runBlocking {
            rules.loadRules()
            val ctx = RuleProcessorFactoryTest.createContext(rules)
            val rp = RuleProcessorFactory.create(ctx, rules.allRules[0].mode)
            rp.process(rules.allRules[0])
            val dmp = (rp as DirectModeProcessor)
            val analyzer = dmp.analyzers[0]
            val tsp = createDefaultTwoStagePointerAnalyze(analyzer.entryMethod)
            tsp.doPointerAnalyze()
            finder = TaintPathFinder(ctx, tsp.ctx, rules.allRules.first() as TaintFlowRule, analyzer)
        }
        return finder
    }

    @Test
    fun analyze() {
        OutputSecResults.testClearVulnerabilityItems()
        val finder = createTwoStagePointerAnalyzerFromRule("unzipslip.json")
        runBlocking {
            finder.findPath()
        }
        Assertions.assertEquals(2, OutputSecResults.vulnerabilityItems().size)
        runBlocking {
            OutputSecResults.processResult(finder.ctx)
        }
    }

    @Test
    fun constStringAnalyze() {
        OutputSecResults.testClearVulnerabilityItems()
        val finder = createTwoStagePointerAnalyzerFromRule("unzipslipFromConstString.json")
        runBlocking {
            finder.findPath()
        }
        Assertions.assertEquals(1, OutputSecResults.vulnerabilityItems().size)
    }

    @Test
    fun pathBetweenMethods() {
        OutputSecResults.testClearVulnerabilityItems()
        val finder = createTwoStagePointerAnalyzerFromRule("another_example.json")
        runBlocking {
            finder.findPath()
        }
        Assertions.assertEquals(1, OutputSecResults.vulnerabilityItems().size)
    }
}
