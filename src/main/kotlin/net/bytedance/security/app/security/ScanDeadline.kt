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

import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

class ScanDeadline private constructor(
    private val scheduler: ScheduledExecutorService,
    private val future: ScheduledFuture<*>,
) : AutoCloseable {
    override fun close() {
        future.cancel(false)
        scheduler.shutdownNow()
    }

    companion object {
        fun start(timeoutSeconds: Long, onTimeout: () -> Unit): ScanDeadline {
            require(timeoutSeconds > 0) { "Scan timeout must be positive" }
            val timeoutMillis = Math.multiplyExact(timeoutSeconds, 1000L)
            val fired = AtomicBoolean(false)
            val scheduler = Executors.newSingleThreadScheduledExecutor { runnable ->
                Thread(runnable, "appshark-scan-deadline").apply {
                    isDaemon = true
                }
            }
            val future = scheduler.schedule(
                {
                    if (fired.compareAndSet(false, true)) {
                        onTimeout()
                    }
                },
                timeoutMillis,
                TimeUnit.MILLISECONDS
            )
            return ScanDeadline(scheduler, future)
        }
    }
}
