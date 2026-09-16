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

import kotlinx.serialization.Serializable
import net.bytedance.security.app.EngineInfo
import net.bytedance.security.app.security.ScanLimitExceededException
import net.bytedance.security.app.security.ScanToolException
import net.bytedance.security.app.security.ScanWorkspace
import net.bytedance.security.app.security.SecurityLimits
import net.bytedance.security.app.util.Json
import net.bytedance.security.app.util.SecureFileIO
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.FileVisitResult
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.SimpleFileVisitor
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.security.MessageDigest
import java.util.Comparator
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

@Serializable
data class JadxCacheMetadata(
    val apkSha256: String,
    val apkBytes: Long,
    val appSharkVersion: String,
    val jadxIdentity: String,
    val argumentDigest: String,
    val complete: Boolean,
)

class JadxRunner {
    fun run(
        executable: Path,
        workspace: ScanWorkspace,
        limits: SecurityLimits,
        configuredThreads: Int?,
        timeoutSeconds: Long,
    ): Path {
        limits.validate()
        require(timeoutSeconds > 0) { "jadx timeout must be positive" }
        require(
            Files.isRegularFile(executable, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(executable)
        ) {
            "jadx executable must be a regular file"
        }

        val threads = limits.effectiveJadxThreads(
            configuredThreads,
            Runtime.getRuntime().availableProcessors()
        )
        val expected = JadxCacheMetadata(
            apkSha256 = workspace.apkSha256,
            apkBytes = workspace.apkBytes,
            appSharkVersion = EngineInfo.Version,
            jadxIdentity = SecureFileIO.sha256(executable, limits.maxApkBytes),
            argumentDigest = argumentDigest(threads),
            complete = true
        )
        val metadataPath = workspace.jadxOutput.resolve(METADATA_FILE)
        if (readReusableMetadata(metadataPath, expected) &&
            inspectOutput(workspace.jadxOutput, limits).regularFiles > 1
        ) {
            return workspace.jadxOutput
        }

        clearDirectory(workspace.jadxOutput)
        val command = listOf(
            executable.toAbsolutePath().normalize().toString(),
            "--quiet",
            "--no-imports",
            "--show-bad-code",
            "--no-debug-info",
            "--output-dir", workspace.jadxOutput.toString(),
            "--threads-count", threads.toString(),
            "--export-gradle",
            workspace.apkSnapshot.toString(),
        )
        val process = try {
            ProcessBuilder(command)
                .redirectOutput(ProcessBuilder.Redirect.INHERIT)
                .redirectError(ProcessBuilder.Redirect.INHERIT)
                .start()
        } catch (e: IOException) {
            throw ScanToolException("Failed to start jadx", e)
        }

        val monitorFailure = AtomicReference<Throwable?>(null)
        val stopMonitor = AtomicBoolean(false)
        val monitor = Thread({
            while (!stopMonitor.get()) {
                try {
                    inspectOutput(workspace.jadxOutput, limits)
                    Thread.sleep(MONITOR_INTERVAL_MILLIS)
                } catch (_: InterruptedException) {
                    return@Thread
                } catch (e: Throwable) {
                    monitorFailure.compareAndSet(null, e)
                    terminateProcessTree(process)
                    return@Thread
                }
            }
        }, "appshark-jadx-output-monitor").apply {
            isDaemon = true
            start()
        }

        try {
            val completed = process.waitFor(timeoutSeconds, TimeUnit.SECONDS)
            if (!completed) {
                terminateProcessTree(process)
                throw ScanToolException("jadx timed out after $timeoutSeconds seconds")
            }
        } catch (e: InterruptedException) {
            terminateProcessTree(process)
            Thread.currentThread().interrupt()
            throw ScanToolException("Interrupted while waiting for jadx", e)
        } finally {
            stopMonitor.set(true)
            monitor.interrupt()
            try {
                monitor.join(TimeUnit.SECONDS.toMillis(2))
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
            }
        }

        monitorFailure.get()?.let { failure ->
            when (failure) {
                is ScanLimitExceededException -> throw failure
                is ScanToolException -> throw failure
                else -> throw ScanToolException("Failed to inspect jadx output", failure)
            }
        }
        if (process.exitValue() != 0) {
            throw ScanToolException("jadx exited with code ${process.exitValue()}")
        }

        val output = inspectOutput(workspace.jadxOutput, limits)
        if (output.regularFiles == 0L) {
            throw ScanToolException("jadx produced no output files")
        }
        publishMetadata(metadataPath, expected)
        return workspace.jadxOutput
    }

    private fun readReusableMetadata(path: Path, expected: JadxCacheMetadata): Boolean {
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(path)) {
            return false
        }
        return try {
            val actual = Json.decodeFromString<JadxCacheMetadata>(
                SecureFileIO.readUtf8(path, MAX_METADATA_BYTES, "jadx cache metadata")
            )
            isReusable(actual, expected)
        } catch (_: Exception) {
            false
        }
    }

    private fun publishMetadata(path: Path, metadata: JadxCacheMetadata) {
        val partial = path.resolveSibling("$METADATA_FILE.part")
        Files.deleteIfExists(partial)
        val bytes = Json.encodeToString(metadata).toByteArray(StandardCharsets.UTF_8)
        try {
            java.nio.channels.FileChannel.open(
                partial,
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE
            ).use { channel ->
                var buffer = ByteBuffer.wrap(bytes)
                while (buffer.hasRemaining()) {
                    channel.write(buffer)
                }
                channel.force(true)
            }
            try {
                Files.move(
                    partial,
                    path,
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING
                )
            } catch (_: AtomicMoveNotSupportedException) {
                Files.move(partial, path, StandardCopyOption.REPLACE_EXISTING)
            }
        } catch (e: IOException) {
            Files.deleteIfExists(partial)
            throw ScanToolException("Failed to publish jadx cache metadata", e)
        }
    }

    private fun inspectOutput(root: Path, limits: SecurityLimits): OutputStats {
        var regularFiles = 0L
        var bytes = 0L
        try {
            Files.walkFileTree(root, object : SimpleFileVisitor<Path>() {
                override fun visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult {
                    if (attrs.isSymbolicLink) {
                        throw ScanToolException("jadx output contains a symbolic link")
                    }
                    if (attrs.isRegularFile) {
                        regularFiles = checkedAdd(regularFiles, 1, "jadx output file count")
                        bytes = checkedAdd(bytes, attrs.size(), "jadx output bytes")
                        if (regularFiles > limits.maxJadxOutputFiles) {
                            throw ScanLimitExceededException(
                                "jadx output file count exceeds limit ${limits.maxJadxOutputFiles}"
                            )
                        }
                        if (bytes > limits.maxJadxOutputBytes) {
                            throw ScanLimitExceededException(
                                "jadx output bytes exceeds limit ${limits.maxJadxOutputBytes}"
                            )
                        }
                    }
                    return FileVisitResult.CONTINUE
                }
            })
        } catch (e: ScanLimitExceededException) {
            throw e
        } catch (e: ScanToolException) {
            throw e
        } catch (e: IOException) {
            throw ScanToolException("Failed to inspect jadx output", e)
        }
        return OutputStats(regularFiles, bytes)
    }

    private fun clearDirectory(root: Path) {
        try {
            Files.walkFileTree(root, object : SimpleFileVisitor<Path>() {
                override fun visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult {
                    Files.delete(file)
                    return FileVisitResult.CONTINUE
                }

                override fun postVisitDirectory(dir: Path, exc: IOException?): FileVisitResult {
                    if (exc != null) {
                        throw exc
                    }
                    if (dir != root) {
                        Files.delete(dir)
                    }
                    return FileVisitResult.CONTINUE
                }
            })
        } catch (e: IOException) {
            throw ScanToolException("Failed to clear jadx output directory", e)
        }
    }

    private fun terminateProcessTree(process: Process) {
        val descendants = process.toHandle().descendants().toArray()
            .map { it as ProcessHandle }
            .sortedWith(Comparator.comparingInt<ProcessHandle> { processDepth(it) }.reversed())
        descendants.forEach { it.destroy() }
        process.destroy()
        try {
            if (!process.waitFor(2, TimeUnit.SECONDS)) {
                descendants.forEach { if (it.isAlive) it.destroyForcibly() }
                process.destroyForcibly()
                process.waitFor(2, TimeUnit.SECONDS)
            }
        } catch (e: InterruptedException) {
            descendants.forEach { if (it.isAlive) it.destroyForcibly() }
            process.destroyForcibly()
            Thread.currentThread().interrupt()
        }
    }

    private fun processDepth(handle: ProcessHandle): Int {
        var depth = 0
        var current = handle.parent()
        while (current.isPresent) {
            depth++
            current = current.get().parent()
        }
        return depth
    }

    private fun checkedAdd(current: Long, amount: Long, name: String): Long =
        try {
            Math.addExact(current, amount)
        } catch (e: ArithmeticException) {
            throw ScanLimitExceededException("$name exceeds supported range")
        }

    private data class OutputStats(val regularFiles: Long, val bytes: Long)

    companion object {
        private const val METADATA_FILE = "cache-metadata.json"
        private const val MAX_METADATA_BYTES = 64L * 1024
        private const val MONITOR_INTERVAL_MILLIS = 250L

        internal fun isReusable(
            actual: JadxCacheMetadata,
            expected: JadxCacheMetadata
        ): Boolean = actual.complete && actual == expected

        internal fun argumentDigest(threads: Int): String {
            require(threads > 0) { "jadx thread count must be positive" }
            val stableArguments = listOf(
                "--quiet",
                "--no-imports",
                "--show-bad-code",
                "--no-debug-info",
                "--output-dir", "<JADX_OUTPUT>",
                "--threads-count", threads.toString(),
                "--export-gradle",
                "<APK_SNAPSHOT>",
            )
            return MessageDigest.getInstance("SHA-256")
                .digest(stableArguments.joinToString("\u0000").toByteArray(StandardCharsets.UTF_8))
                .joinToString("") { byte ->
                    (byte.toInt() and 0xff).toString(16).padStart(2, '0')
                }
        }
    }
}
