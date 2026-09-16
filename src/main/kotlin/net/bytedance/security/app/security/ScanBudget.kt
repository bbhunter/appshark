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

class ScanBudget(val limits: SecurityLimits) {
    private var analyzers = 0L
    private var results = 0L
    private var reports = 0L
    private var reportBytes = 0L
    private var logBytes = 0L

    init {
        limits.validate()
    }

    @Synchronized
    fun reserveAnalyzers(count: Int) {
        analyzers = reserve("Analyzer count", analyzers, count.toLong(), limits.maxTotalAnalyzers.toLong())
    }

    @Synchronized
    fun reserveResult() {
        results = reserve("Result count", results, 1, limits.maxResultCount.toLong())
    }

    @Synchronized
    fun reserveReport(bytes: Long) {
        require(bytes >= 0) { "Report byte reservation must not be negative" }
        val nextReports = checkedAdd(reports, 1, "Report count")
        val nextBytes = checkedAdd(reportBytes, bytes, "Report bytes")
        if (nextReports > limits.maxReportFiles) {
            throw ScanLimitExceededException(
                "Report count exceeds limit ${limits.maxReportFiles}"
            )
        }
        if (nextBytes > limits.maxReportBytes) {
            throw ScanLimitExceededException(
                "Report bytes exceed limit ${limits.maxReportBytes}"
            )
        }
        reports = nextReports
        reportBytes = nextBytes
    }

    @Synchronized
    fun reserveLog(bytes: Long) {
        logBytes = reserve("Log bytes", logBytes, bytes, limits.maxLogBytes)
    }

    fun sanitizeLogText(value: String): String {
        val escaped = buildString {
            value.forEach { ch ->
                when {
                    ch == '\t' -> append(ch)
                    ch.isISOControl() -> append("\\u%04X".format(ch.code))
                    else -> append(ch)
                }
            }
        }
        if (escaped.length <= limits.maxLogLineChars) {
            return escaped
        }
        if (limits.maxLogLineChars <= ELLIPSIS.length) {
            return ELLIPSIS.take(limits.maxLogLineChars)
        }
        return escaped.take(limits.maxLogLineChars - ELLIPSIS.length) + ELLIPSIS
    }

    @Synchronized
    fun analyzerCount(): Long = analyzers

    private fun reserve(name: String, current: Long, amount: Long, limit: Long): Long {
        require(amount >= 0) { "$name reservation must not be negative" }
        val next = checkedAdd(current, amount, name)
        if (next > limit) {
            throw ScanLimitExceededException("$name exceeds limit $limit")
        }
        return next
    }

    private fun checkedAdd(current: Long, amount: Long, name: String): Long =
        try {
            Math.addExact(current, amount)
        } catch (e: ArithmeticException) {
            throw ScanLimitExceededException("$name exceeds supported range")
        }

    companion object {
        private const val ELLIPSIS = "..."
    }
}
