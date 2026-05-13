// wgbridge-native-aar — Gradle library module that packages the
// hand-rolled libwgbridge_native.so files (built by
// ../wgbridge_native/build.sh via NDK + cgo, NO gomobile) into an
// AAR consumable from the app module.
//
// Why a library module rather than a flat-file dependency:
// Android Gradle Plugin only honors an AAR's `jni/` payload when
// the AAR arrives via a Maven or project dependency.
// `implementation(files(libwgbridge_native.so))` would put the .so
// on the classpath but NOT into the final APK's `lib/<abi>/`
// directories — at runtime System.loadLibrary fails.
//
// The library has zero Kotlin/Java source: the JNI surface lives
// inside the `.so` (Java_*WgBridgeNative_*), and Kotlin-side
// `external` declarations live in the consumer (`app/`). This
// keeps build-time decoupling clean: rebuilding the .so via
// `wgbridge_native/build.sh` is sufficient — Gradle picks up the
// new bytes on the next merge.

plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "com.gutschke.wgrtc.wgbridgenative"
    compileSdk = 35

    defaultConfig {
        minSdk = 26
        // No instrumented tests in this module — the consumer
        // (app) drives the .so via its own androidTest sourceSet.
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    // Pull the .so files from wgbridge_native's build output. The
    // `jniLibs.srcDirs` setting tells AGP to package every `.so`
    // under `<dir>/<abi>/` into the AAR's `jni/<abi>/` payload.
    sourceSets {
        getByName("main") {
            jniLibs.srcDirs("${rootDir}/wgbridge_native/build/jni")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

// Pre-build sanity: fail loud if the wgbridge_native build hasn't
// been run yet, with a precise hint at the fix. AGP's own error
// for missing .so libs is "Failed to find AAR <path>" which is
// useless for debugging.
abstract class CheckWgbridgeNativeBuilt : org.gradle.api.DefaultTask() {
    @get:org.gradle.api.tasks.InputDirectory
    @get:org.gradle.api.tasks.PathSensitive(org.gradle.api.tasks.PathSensitivity.RELATIVE)
    abstract val jniDir: org.gradle.api.file.DirectoryProperty

    @org.gradle.api.tasks.TaskAction
    fun verify() {
        val d = jniDir.get().asFile
        val arm64 = d.resolve("arm64-v8a/libwgbridge_native.so")
        val x86_64 = d.resolve("x86_64/libwgbridge_native.so")
        val missing = listOf(arm64, x86_64).filterNot { it.exists() }
        check(missing.isEmpty()) {
            """
            wgbridge_native .so files missing:
              ${missing.joinToString("\n ") { it.absolutePath }}
            Build them first:
              cd ../wgbridge_native && ./build.sh
            """.trimIndent()
        }
    }
}

val checkNative = tasks.register<CheckWgbridgeNativeBuilt>("checkWgbridgeNativeBuilt") {
    jniDir.set(file("${rootDir}/wgbridge_native/build/jni"))
}

afterEvaluate {
    tasks.named("preBuild") {
        dependsOn(checkNative)
    }
}
