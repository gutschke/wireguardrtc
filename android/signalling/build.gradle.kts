// signalling/ — pure protocol module that talks to a wireguardrtc daemon
// over a PeerJS broker. Uses libsodium (lazysodium-android) for crypto,
// okhttp for the WebSocket transport, kotlinx.serialization for JSON.
//
// Architecturally we keep the API surface free of Android-specific
// types so a future Kotlin Multiplatform port to JVM/iOS stays cheap.
// The crypto dep is currently lazysodium-android (not pure JVM); a
// later refactor can swap to bouncycastle for KMP.

plugins {
 alias(libs.plugins.android.library)
 alias(libs.plugins.kotlin.android)
 alias(libs.plugins.kotlin.serialization)
}

android {
 namespace = "com.gutschke.wgrtc.signalling"
 compileSdk = 35

 defaultConfig {
 minSdk = 26
 }

 compileOptions {
 sourceCompatibility = JavaVersion.VERSION_17
 targetCompatibility = JavaVersion.VERSION_17
 }
 kotlinOptions {
 jvmTarget = "17"
 }

 // Pure-JVM unit tests under src/test/kotlin/. Per the module-level
 // refactor (EnrollUri + EnrollClient now use java.util.Base64 and
 // a hand-rolled URI parser, no `android.*` imports) these tests run
 // on the host JVM without Robolectric. Crypto + EnrollClient tests
 // that need libsodium are still pending an injectable-Sodium
 // refactor —
 testOptions {
 unitTests.all {
 it.useJUnitPlatform()
 }
 }
}

dependencies {
 implementation(libs.kotlinx.coroutines.android)
 implementation(libs.kotlinx.coroutines.core)
 implementation(libs.kotlinx.serialization.json)
 implementation(libs.okhttp)
 // lazysodium-android pulls in JNA 5.17.0 transitively, but as the
 // plain JAR — no `libjnidispatch.so`. Without the AAR variant the
 // app crashes at first crypto call with `UnsatisfiedLinkError:
 // Native library (com/sun/jna/android-x86-64/libjnidispatch.so)
 // not found in resource path (.)`. Exclude the transitive JNA
 // and add the @aar variant ourselves; AAR carries the same classes
 // *and* the .so for each ABI.
 implementation(libs.lazysodium.android) {
 exclude(group = "net.java.dev.jna", module = "jna")
 }
 implementation("net.java.dev.jna:jna:5.17.0@aar")

 testImplementation(libs.junit.jupiter)
 testImplementation(libs.kotlinx.coroutines.test)
 testImplementation(libs.okhttp.mockwebserver)
 // LazySodiumJava for plain-JVM crypto tests. Pulls JNA as a regular
 // jar (no @aar variant needed; the .so is loaded from the libsodium
 // JNA shim, not from an AAR's jniLibs).
 testImplementation(libs.lazysodium.java)
}
