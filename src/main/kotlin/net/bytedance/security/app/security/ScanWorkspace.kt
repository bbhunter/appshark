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

import net.bytedance.security.app.util.SecureFileIO
import java.nio.charset.StandardCharsets
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermission
import java.util.EnumSet
import java.util.UUID

class ScanWorkspace private constructor(
    val root: Path,
    val apkSnapshot: Path,
    val apkSha256: String,
    val apkBytes: Long,
    val jadxOutput: Path,
    private val ownerToken: String,
) : AutoCloseable {
    private var closed = false

    override fun close() {
        if (closed) {
            return
        }
        SecureFileIO.deleteOwnedTree(root, OWNER_MARKER, ownerToken)
        closed = true
    }

    companion object {
        private const val OWNER_MARKER = ".appshark-owner"

        fun create(outRoot: Path, sourceApk: Path, limits: SecurityLimits): ScanWorkspace {
            limits.validate()
            ApkPreflight.inspect(sourceApk, limits)

            val normalizedOut = outRoot.toAbsolutePath().normalize()
            require(!Files.isSymbolicLink(normalizedOut)) {
                "Output root must not be a symbolic link"
            }
            Files.createDirectories(normalizedOut)
            require(Files.isDirectory(normalizedOut, LinkOption.NOFOLLOW_LINKS)) {
                "Output root must be a directory"
            }

            val workRoot = normalizedOut.resolve(".appshark-work")
            require(!Files.isSymbolicLink(workRoot)) {
                "Workspace root must not be a symbolic link"
            }
            Files.createDirectories(workRoot)
            require(Files.isDirectory(workRoot, LinkOption.NOFOLLOW_LINKS)) {
                "Workspace root must be a directory"
            }

            val taskRoot = Files.createTempDirectory(workRoot, "task-")
            setOwnerOnlyPermissions(taskRoot)
            val ownerToken = UUID.randomUUID().toString()
            Files.writeString(
                taskRoot.resolve(OWNER_MARKER),
                ownerToken,
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE
            )

            try {
                val partial = taskRoot.resolve("input.apk.part")
                val snapshot = taskRoot.resolve("input.apk")
                val digest = SecureFileIO.copyAndSha256(
                    sourceApk,
                    partial,
                    limits.maxApkBytes
                )
                moveWithoutReplace(partial, snapshot)
                val report = ApkPreflight.inspect(snapshot, limits)
                val jadxOutput = Files.createDirectory(taskRoot.resolve("jadx"))
                return ScanWorkspace(
                    root = taskRoot,
                    apkSnapshot = snapshot,
                    apkSha256 = digest,
                    apkBytes = report.apkBytes,
                    jadxOutput = jadxOutput,
                    ownerToken = ownerToken
                )
            } catch (e: Exception) {
                SecureFileIO.deleteOwnedTree(taskRoot, OWNER_MARKER, ownerToken)
                throw e
            }
        }

        private fun moveWithoutReplace(source: Path, target: Path) {
            try {
                Files.move(source, target, StandardCopyOption.ATOMIC_MOVE)
            } catch (_: AtomicMoveNotSupportedException) {
                Files.move(source, target)
            }
        }

        private fun setOwnerOnlyPermissions(path: Path) {
            try {
                Files.setPosixFilePermissions(
                    path,
                    EnumSet.of(
                        PosixFilePermission.OWNER_READ,
                        PosixFilePermission.OWNER_WRITE,
                        PosixFilePermission.OWNER_EXECUTE
                    )
                )
            } catch (_: UnsupportedOperationException) {
                // The no-symlink and ownership-token checks remain active on non-POSIX systems.
            }
        }
    }
}
