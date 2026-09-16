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

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.jsonObject
import net.bytedance.security.app.RuleData
import net.bytedance.security.app.util.Json
import net.bytedance.security.app.util.SecureFileIO
import java.nio.file.Files
import java.nio.file.Path
import java.util.ArrayDeque

class RuleLoadContext(
    ruleRoot: Path,
    private val limits: SecurityLimits,
) {
    private val root = ruleRoot.toRealPath()
    private val parsed = LinkedHashMap<Path, JsonObject>()
    private val digests = HashMap<Path, String>()
    private val active = ArrayDeque<Path>()
    private val seenFiles = HashSet<Path>()
    private val ruleNames = HashSet<String>()
    private var totalBytes = 0L
    private var referenceCount = 0

    init {
        limits.validate()
    }

    fun loadTopLevel(paths: List<Path>): List<Pair<Path, JsonObject>> =
        paths.map { path ->
            val resolved = resolveTopLevel(path)
            resolved to loadPath(resolved, 1)
        }

    fun loadReferenced(reference: String): JsonObject {
        validateReference(reference)
        referenceCount = checkedAdd(referenceCount, 1, "Rule reference count")
        require(referenceCount <= limits.maxRuleReferences) {
            "Rule references exceed maximum count of ${limits.maxRuleReferences}"
        }
        return loadPath(SecureFileIO.resolveRuleFile(root, reference), active.size + 1)
    }

    fun digest(path: Path): String {
        val resolved = resolveTopLevel(path)
        return requireNotNull(digests[resolved]) { "Rule file has not been loaded" }
    }

    fun ruleDigests(): Map<String, String> =
        digests.entries
            .associate { (path, digest) -> root.relativize(path).toString() to digest }
            .toSortedMap()

    private fun loadPath(path: Path, depth: Int): JsonObject {
        require(depth <= limits.maxRuleReferenceDepth) {
            "Rule reference depth exceeds maximum of ${limits.maxRuleReferenceDepth}"
        }
        require(!active.contains(path)) { "Rule reference cycle detected" }
        parsed[path]?.let { return it }

        if (seenFiles.add(path)) {
            require(seenFiles.size <= limits.maxRuleFiles) {
                "Rule files exceed maximum count of ${limits.maxRuleFiles}"
            }
            totalBytes = checkedAdd(totalBytes, Files.size(path), "Rule total bytes")
            require(totalBytes <= limits.maxRuleTotalBytes) {
                "Rules exceed maximum total size of ${limits.maxRuleTotalBytes} bytes"
            }
        }

        active.addLast(path)
        try {
            val jsonString = SecureFileIO.readUtf8(
                path,
                minOf(SecureFileIO.MAX_RULE_FILE_BYTES, limits.maxRuleTotalBytes),
                "Rule file"
            )
            val jsonObject = try {
                val parsedObject = Json.parseToJsonElement(jsonString).jsonObject
                validateElement(parsedObject)

                for ((ruleName, ruleElement) in parsedObject) {
                    validateRuleName(ruleName)
                    require(ruleNames.add(ruleName)) { "Duplicate rule name is not allowed" }
                    val ruleData: RuleData = Json.decodeFromJsonElement(ruleElement)
                    referencedFiles(ruleData).forEach { reference ->
                        loadReferenced(reference)
                    }
                }
                parsedObject
            } catch (e: IllegalArgumentException) {
                throw e
            } catch (e: Exception) {
                throw IllegalArgumentException(
                    "Invalid rule file: ${root.relativize(path)}",
                    e
                )
            }

            digests[path] = SecureFileIO.sha256(path, SecureFileIO.MAX_RULE_FILE_BYTES)
            parsed[path] = jsonObject
            return jsonObject
        } finally {
            active.removeLast()
        }
    }

    private fun resolveTopLevel(path: Path): Path {
        val candidate = if (path.isAbsolute) {
            path.toAbsolutePath().normalize()
        } else {
            root.resolve(path).normalize()
        }
        require(Files.isRegularFile(candidate)) { "Rule file is not a regular file" }
        val realPath = candidate.toRealPath()
        require(realPath.startsWith(root)) { "Rule file escapes rulePath" }
        val relative = root.relativize(realPath).toString()
        return SecureFileIO.resolveRuleFile(root, relative)
    }

    private fun referencedFiles(ruleData: RuleData): Sequence<String> =
        sequenceOf(ruleData.sourceRuleObj, ruleData.sinkRuleObj)
            .filterNotNull()
            .flatten()
            .map {
                requireNotNull(it.ruleFile) { "Nested rule reference is missing ruleFile" }
            }

    private fun validateReference(reference: String) {
        require(reference.isNotBlank()) { "Rule file reference is empty" }
        require(reference.none(Char::isISOControl)) {
            "Rule file reference contains control characters"
        }
    }

    private fun validateRuleName(ruleName: String) {
        require(ruleName.isNotBlank()) { "Rule name is empty" }
        require(ruleName.length <= limits.maxRuleStringChars) {
            "Rule name exceeds maximum length"
        }
        require(ruleName.none(Char::isISOControl)) {
            "Rule name contains control characters"
        }
    }

    private fun validateElement(element: JsonElement) {
        when (element) {
            is JsonObject -> {
                require(element.size <= limits.maxRuleCollectionEntries) {
                    "Rule object exceeds maximum entry count"
                }
                element.forEach { (key, value) ->
                    require(key.length <= limits.maxRuleStringChars) {
                        "Rule object key exceeds maximum length"
                    }
                    require(key.none(Char::isISOControl)) {
                        "Rule object key contains control characters"
                    }
                    validateElement(value)
                }
            }

            is JsonArray -> {
                require(element.size <= limits.maxRuleCollectionEntries) {
                    "Rule array exceeds maximum entry count"
                }
                element.forEach(::validateElement)
            }

            is JsonPrimitive -> validatePrimitive(element)
        }
    }

    private fun validatePrimitive(primitive: JsonPrimitive) {
        if (primitive.isString) {
            require(primitive.content.length <= limits.maxRuleStringChars) {
                "Rule string exceeds maximum length"
            }
            return
        }
        if (primitive === JsonNull || primitive.booleanOrNull != null) {
            return
        }
        primitive.content.toDoubleOrNull()?.let {
            require(it.isFinite()) { "Rule number must be finite" }
        }
    }

    private fun checkedAdd(current: Int, amount: Int, description: String): Int =
        try {
            Math.addExact(current, amount)
        } catch (e: ArithmeticException) {
            throw IllegalArgumentException("$description exceeds supported range", e)
        }

    private fun checkedAdd(current: Long, amount: Long, description: String): Long =
        try {
            Math.addExact(current, amount)
        } catch (e: ArithmeticException) {
            throw IllegalArgumentException("$description exceeds supported range", e)
        }
}
