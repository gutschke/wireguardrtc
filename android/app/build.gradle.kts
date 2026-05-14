import java.util.Properties
import java.util.zip.ZipEntry
import java.util.zip.ZipFile

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
}

// Optional Play-Store-upload signing config. Reads from a
// gitignored `app/keystore.properties`; absent file → release
// builds fall back to the debug keystore so `assembleRelease` still
// works for local smoke-testing. See ../reference/PLAY_STORE_NOTES.md.
val keystorePropertiesFile = rootProject.file("app/keystore.properties")
val keystoreProperties = Properties().apply {
    if (keystorePropertiesFile.exists()) {
        keystorePropertiesFile.inputStream().use { load(it) }
    }
}
val haveReleaseKeystore = keystoreProperties.getProperty("storeFile") != null

android {
    namespace = "com.gutschke.wgrtc"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.gutschke.wgrtc"
        minSdk = 26
        targetSdk = 35
        versionCode = 25
        versionName = "0.2.4"
        // Instrumented (androidTest) tests use AndroidX Test's JUnit 4
        // runner. The connectedDebugAndroidTest task drives them via
        // ADB against whichever device/emulator is currently attached.
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // Match what wgbridge_native/build.sh produces. Without this
        // filter, transitive dependencies (libsodium-jni etc.) leak
        // 32-bit ABIs (armeabi-v7a, x86) into the APK as shells —
        // without libwgbridge_native.so, the app would install on a
        // 32-bit device and crash at first JNI call.  32-bit users
        // are documented in RELEASING.md as a build-from-source case.
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    signingConfigs {
        if (haveReleaseKeystore) {
            create("release") {
                storeFile = file(keystoreProperties["storeFile"] as String)
                storePassword = keystoreProperties["storePassword"] as String
                keyAlias = keystoreProperties["keyAlias"] as String
                keyPassword = keystoreProperties["keyPassword"] as String
            }
        }
    }

    buildFeatures {
        compose = true
        // Generates com.gutschke.wgrtc.BuildConfig with DEBUG/etc; the
        // mintHostEnrollToken path uses BuildConfig.DEBUG to gate a
        // debug-only URI dump so agentic test rigs can grab the
        // enrollment string straight from logcat (release elides it).
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    buildTypes {
        debug {
            applicationIdSuffix = ".debug"
            isDebuggable = true
        }
        release {
            // Code shrinking deferred — gomobile-bound classes need
            // explicit keep rules and the gain (~5 MB) isn't worth
            // the regression risk for a small-audience build.
            isMinifyEnabled = false
            // Pick up the Play-Store upload key when present;
            // otherwise (developers without the keystore) fall back
            // to debug signing so the build doesn't break.
            signingConfig = signingConfigs.findByName("release")
                ?: signingConfigs.getByName("debug")
        }
        // Instrumented test channel — picks up `src/agent/` source
        // set on top of `src/main/`, which adds a broadcast receiver
        // + content provider that let an attached adb host drive the
        // app without going through the UI. NEVER ship: separate
        // applicationId means Play Store + GitHub release builds can
        // never collide with this, and `src/agent/` is physically
        // absent from `assembleDebug` / `assembleRelease`, so a
        // signature scan of the production AAB has nothing to find.
        // The companion `verifyAgentNotInRelease` task below double-
        // checks the release dex.
        create("agent") {
            initWith(getByName("debug"))
            applicationIdSuffix = ".agent"
            isDebuggable = true
            matchingFallbacks += listOf("debug")
        }
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }

    // Pure-JVM unit tests under src/test/kotlin/. TunnelStore now
    // takes a File rather than a Context, and renderEnrollConfig moved
    // to data/EnrollConfigRenderer.kt as a pure function — both can
    // run on a plain JVM. isReturnDefaultValues=true keeps incidental
    // android.util.Log calls from throwing. ViewModel + UI tests
    // would need Robolectric/instrumentation and are deferred.
    testOptions {
        unitTests.isReturnDefaultValues = true
        unitTests.all {
            it.useJUnitPlatform()
        }
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime)
    implementation(libs.androidx.activity.compose)
    implementation(libs.kotlinx.coroutines.android)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons.extended)
    implementation(libs.androidx.navigation.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.zxing.embedded)
    implementation(project(":signalling"))
    // + libwgbridge_native.so (cgo + //export build of
    // golang.zx2c4.com/wireguard, built by ../wgbridge_native/build.sh
    // and packaged by :wgbridge-native-aar) is the only userspace WG
    // runtime we ship. Both the gomobile-built :wgbridge-aar and
    // the wireguard-android `wg-tunnel` dep have been removed.
    implementation(project(":wgbridge-native-aar"))

    testImplementation(libs.junit.jupiter)
    testImplementation(libs.kotlinx.coroutines.test)
    // lazysodium-java provides a pure-JVM libsodium for tests that
    // exercise X25519/secretbox. Production uses lazysodium-android
    // (different jar, same API) — the Sodium.setForTest seam swaps
    // them transparently.
    testImplementation(libs.lazysodium.java)

    // Instrumented test deps (androidTest sourceSet). JUnit 4 + the
    // AndroidX Test wrappers — Jupiter's AndroidJUnitRunner story is
    // fragile, so the instrumented suite uses JUnit 4 even though
    // our JVM unit suite is on Jupiter.
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.rules)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.junit4)
    androidTestImplementation(libs.kotlinx.coroutines.test)
}

// Belt-and-suspenders gate for the agent buildType: the source-set
// split already excludes `src/agent/` from any other build, but if
// someone ever moves the receiver into `src/main/` by accident this
// task fails the release build before an AAB can be uploaded.
tasks.register("verifyAgentNotInRelease") {
    group = "verification"
    description =
        "Asserts no com/gutschke/wgrtc/agent/ classes leak into the release APK."
    dependsOn("assembleRelease")
    // Capture once at configuration time so the action closure only
    // holds configuration-cache-safe types (File, ByteArray). Defining
    // containsBytes at script scope captures the Project reference into
    // the doLast closure, which fails the config cache — inline it.
    val apkDirFile = layout.buildDirectory
        .dir("outputs/apk/release").get().asFile
    val needle = "com/gutschke/wgrtc/agent/".toByteArray(Charsets.UTF_8)
    doLast {
        fun containsBytes(haystack: ByteArray, n: ByteArray): Boolean {
            if (n.isEmpty() || haystack.size < n.size) return false
            outer@ for (i in 0..haystack.size - n.size) {
                for (j in n.indices) {
                    if (haystack[i + j] != n[j]) continue@outer
                }
                return true
            }
            return false
        }
        val apks = apkDirFile.listFiles { f -> f.name.endsWith(".apk") }
            .orEmpty()
        require(apks.isNotEmpty()) {
            "expected at least one APK under ${apkDirFile.absolutePath}"
        }
        for (apk in apks) {
            ZipFile(apk).use { zip ->
                val dexes: List<ZipEntry> = zip.entries().toList()
                    .filter { entry: ZipEntry ->
                        entry.name.matches(Regex("classes\\d*\\.dex"))
                    }
                require(dexes.isNotEmpty()) {
                    "no classes*.dex inside ${apk.name}"
                }
                for (dex in dexes) {
                    val bytes = zip.getInputStream(dex).readBytes()
                    check(!containsBytes(bytes, needle)) {
                        "agent classes leaked into release: " +
                            "${apk.name} :: ${dex.name}"
                    }
                }
            }
        }
        println("verifyAgentNotInRelease: clean")
    }
}
