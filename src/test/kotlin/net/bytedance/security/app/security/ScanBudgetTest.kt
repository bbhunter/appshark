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
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

internal class ScanBudgetTest {
    @AfterEach
    fun clearRuntime() {
        ScanRuntime.clear()
    }

    @Test
    fun `exact analyzer result and report limits succeed and one more fails`() {
        val budget = ScanBudget(
            SecurityLimits(
                maxTotalAnalyzers = 2,
                maxResultCount = 2,
                maxReportFiles = 2,
                maxReportBytes = 4
            ).validate()
        )

        budget.reserveAnalyzers(2)
        budget.reserveResult()
        budget.reserveResult()
        budget.reserveReport(2)
        budget.reserveReport(2)

        assertThrows(ScanLimitExceededException::class.java) {
            budget.reserveAnalyzers(1)
        }
        assertThrows(ScanLimitExceededException::class.java) {
            budget.reserveResult()
        }
        assertThrows(ScanLimitExceededException::class.java) {
            budget.reserveReport(1)
        }
    }

    @Test
    fun `negative reservations are rejected`() {
        val budget = ScanBudget(SecurityLimits())

        assertThrows(IllegalArgumentException::class.java) {
            budget.reserveAnalyzers(-1)
        }
        assertThrows(IllegalArgumentException::class.java) {
            budget.reserveReport(-1)
        }
        assertThrows(IllegalArgumentException::class.java) {
            budget.reserveLog(-1)
        }
    }

    @Test
    fun `concurrent analyzer reservations cannot exceed the limit`() {
        val budget = ScanBudget(SecurityLimits(maxTotalAnalyzers = 100).validate())
        val executor = Executors.newFixedThreadPool(10)
        val start = CountDownLatch(1)
        val done = CountDownLatch(10)

        repeat(10) {
            executor.execute {
                start.await()
                repeat(10) {
                    budget.reserveAnalyzers(1)
                }
                done.countDown()
            }
        }
        start.countDown()

        assertEquals(true, done.await(5, TimeUnit.SECONDS))
        executor.shutdownNow()
        assertEquals(100, budget.analyzerCount())
        assertThrows(ScanLimitExceededException::class.java) {
            budget.reserveAnalyzers(1)
        }
    }

    @Test
    fun `untrusted log text is single line escaped and bounded`() {
        val budget = ScanBudget(
            SecurityLimits(maxLogLineChars = 10, maxLogBytes = 1024).validate()
        )

        val sanitized = budget.sanitizeLogText("a\u001Bb\n0123456789")

        assertEquals("a\\u001B...", sanitized)
        assertFalse(sanitized.contains('\u001B'))
        assertFalse(sanitized.contains('\n'))
    }

    @Test
    fun `log bytes are bounded`() {
        val budget = ScanBudget(SecurityLimits(maxLogBytes = 4).validate())

        budget.reserveLog(4)

        assertThrows(ScanLimitExceededException::class.java) {
            budget.reserveLog(1)
        }
    }

    @Test
    fun `scan runtime rejects concurrent installation`() {
        val out = Files.createTempDirectory("appshark-budget")
        val apk = zipOf("classes.dex" to ByteArray(8))
        val workspace = ScanWorkspace.create(out, apk, testLimits())
        val budget = ScanBudget(SecurityLimits())

        try {
            ScanRuntime.install(budget, workspace)
            assertEquals(budget, ScanRuntime.budget())
            assertEquals(workspace, ScanRuntime.workspace())
            assertThrows(IllegalStateException::class.java) {
                ScanRuntime.install(ScanBudget(SecurityLimits()), workspace)
            }
        } finally {
            ScanRuntime.clear()
            workspace.close()
        }
    }
}
