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


package net.bytedance.security.app

import kotlinx.coroutines.runBlocking
import net.bytedance.security.app.Fragment.Companion.processFragmentEntries
import net.bytedance.security.app.Log.logInfo
import net.bytedance.security.app.android.AndroidUtils
import net.bytedance.security.app.android.AndroidUtils.loadDynamicRegisterReceiver
import net.bytedance.security.app.android.AndroidUtils.parseApk
import net.bytedance.security.app.engineconfig.EngineConfig
import net.bytedance.security.app.result.OutputSecResults
import net.bytedance.security.app.security.ScanBudget
import net.bytedance.security.app.security.ScanDeadline
import net.bytedance.security.app.security.ScanLimitExceededException
import net.bytedance.security.app.security.ScanOutputException
import net.bytedance.security.app.security.ScanRuntime
import net.bytedance.security.app.security.ScanToolException
import net.bytedance.security.app.security.ScanWorkspace
import net.bytedance.security.app.util.Json
import net.bytedance.security.app.util.SecureFileIO
import net.bytedance.security.app.util.profiler
import java.nio.file.Paths
import kotlin.system.exitProcess

internal interface ScanExecutor {
    suspend fun execute(config: ArgumentConfig)
}

object StaticAnalyzeMain {
    @Throws(Exception::class)
    suspend fun startAnalyze(argumentConfig: ArgumentConfig) {
        val apkPath = argumentConfig.apkPath
        val v3 = AnalyzeStepByStep()
        val jadxPath = "${argumentConfig.configPath}/tools/jadx/bin/"
        val apkNameTool = "${argumentConfig.configPath}/tools/ApkName.sh"

        logInfo("started...")
        profiler.startMemoryProfile()
        val preparedRules = v3.prepareRules(argumentConfig.rules)
        logInfo("rule graph validated")
        v3.initSoot(
            AnalyzeStepByStep.TYPE.APK,
            apkPath,
            "${argumentConfig.configPath}/tools/platforms",
            argumentConfig.outPath
        )
        logInfo("soot init done")
        PLUtils.createCustomClass()
        profiler.parseApk.start()
        parseApk(ScanRuntime.workspace(), jadxPath, apkNameTool)
        logInfo("apk parse done")
        profiler.parseApk.end()

        profiler.preProcessor.start()
        val rules = v3.loadRules(
            preparedRules,
            AndroidUtils.TargetSdk,
            AndroidUtils.MinSdk
        )
        val provenance = LinkedHashMap<String, String>()
        val workspace = ScanRuntime.workspace()
        provenance["apkSha256"] = workspace.apkSha256
        rules.ruleDigests().forEach { (path, digest) ->
            provenance["ruleSha256:$path"] = digest
        }
        OutputSecResults.setAppInfoOther(provenance)
        logInfo("rules loaded")
        val ctx = v3.createContext(rules)
        profiler.preProcessor.end()

        if (getConfig().doWholeProcessMode) {
            PLUtils.createWholeProgramAnalyze(ctx)
        }
        loadDynamicRegisterReceiver(ctx)

        if (argumentConfig.supportFragment) {
            profiler.fragments.start()
            processFragmentEntries(ctx)
            profiler.fragments.end()
        }
        AndroidUtils.initLifeCycle()
        //build call graph of CUSTOM_CLASS
        ctx.buildCustomClassCallGraph(rules)
        val analyzers = v3.parseRules(ctx, rules)
        v3.solve(ctx, analyzers)
        profiler.stopMemoryProfile()
    }
}

private object ProductionScanExecutor : ScanExecutor {
    override suspend fun execute(config: ArgumentConfig) {
        StaticAnalyzeMain.startAnalyze(config)
    }
}

internal fun runCli(
    args: Array<String>,
    executor: ScanExecutor = ProductionScanExecutor
): Int {
    if (args.isEmpty()) {
        println("Usage: java -jar appshark.jar  config.json5")
        return 0
    }
    try {
        val argumentConfig = try {
            val configJson = SecureFileIO.readUtf8(
                Paths.get(args[0]),
                SecureFileIO.MAX_ARGUMENT_CONFIG_BYTES,
                "Argument config"
            )
            Json.decodeFromString<ArgumentConfig>(configJson)
        } catch (e: Exception) {
            throw IllegalArgumentException("Invalid argument config", e)
        }
        ArgumentConfig.mergeWithDefaultConfig(argumentConfig)
        argumentConfig.validate()
        cfg = argumentConfig
        Log.setLevel(argumentConfig.logLevel)

        val limits = argumentConfig.securityLimits
        val deadline = ScanDeadline.start(limits.maxScanSeconds) {
            System.err.println("AppShark scan exceeded maxScanSeconds")
            Runtime.getRuntime().halt(124)
        }
        try {
            ScanWorkspace.create(
                Paths.get(argumentConfig.outPath),
                Paths.get(argumentConfig.apkPath),
                limits
            ).use { workspace ->
                val effectiveConfig = argumentConfig.copyForApk(
                    workspace.apkSnapshot.toString()
                )
                cfg = effectiveConfig
                ScanRuntime.install(ScanBudget(limits), workspace)
                logInfo("welcome to appshark ${EngineInfo.Version}")
                effectiveConfig.libraryPackage?.let {
                    if (it.isNotEmpty()) {
                        EngineConfig.libraryConfig.setPackage(it)
                    }
                }
                runBlocking { executor.execute(effectiveConfig) }
            }
        } finally {
            ScanRuntime.clear()
            deadline.close()
        }
        return 0
    } catch (e: ScanLimitExceededException) {
        reportCliFailure(e)
        return 3
    } catch (e: ScanOutputException) {
        reportCliFailure(e)
        return 5
    } catch (e: ScanToolException) {
        reportCliFailure(e)
        return 4
    } catch (e: IllegalArgumentException) {
        reportCliFailure(e)
        return 2
    } catch (e: Exception) {
        reportCliFailure(e)
        return 4
    } catch (_: OutOfMemoryError) {
        System.err.println("ScanLimitExceededException: process memory exhausted")
        return 3
    } catch (_: StackOverflowError) {
        System.err.println("ScanLimitExceededException: process stack exhausted")
        return 3
    }
}

private fun reportCliFailure(error: Exception) {
    val type = error::class.simpleName ?: "Exception"
    val message = sanitizeCliText(error.message ?: "no details")
    System.err.println("$type: $message")
}

private fun sanitizeCliText(value: String): String {
    val escaped = buildString {
        value.forEach { ch ->
            if (ch == '\t' || !ch.isISOControl()) {
                append(ch)
            } else {
                append("\\u%04X".format(ch.code))
            }
        }
    }
    return if (escaped.length <= 4096) escaped else escaped.take(4093) + "..."
}

fun main(args: Array<String>) {
    val status = runCli(args)
    try {
        Log.flushAndClose()
    } catch (_: Exception) {
        if (status == 0) {
            exitProcess(5)
        }
    }
    if (status != 0) {
        exitProcess(status)
    }
}
