import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Version comes from core/Cargo.toml so the app and the binary inside it always match.
val cargoVersion: String = file("../../../core/Cargo.toml").readLines()
    .first { it.startsWith("version = ") }.substringAfter('"').substringBefore('"')
val parts = cargoVersion.split(".").map { it.toIntOrNull() ?: 0 }
val code = parts[0] * 10000 + parts[1] * 100 + parts[2]

// Release signing: a keystore given through the environment (CI secret or a local file).
// Without one the release APK is signed with the debug key (fine for testing; upgrades
// between builds signed with different keys need an uninstall first).
val ks = System.getenv("SG_KEYSTORE")
android {
    namespace = "io.shellgate.app"
    compileSdk = 35
    defaultConfig {
        applicationId = "io.shellgate.app"
        minSdk = 24
        targetSdk = 34
        versionCode = code
        versionName = cargoVersion
    }
    signingConfigs {
        if (ks != null && file(ks).exists()) {
            create("rel") {
                storeFile = file(ks)
                storePassword = System.getenv("SG_KEYSTORE_PASS")
                keyAlias = System.getenv("SG_KEY_ALIAS") ?: "shellgate"
                keyPassword = System.getenv("SG_KEY_PASS") ?: System.getenv("SG_KEYSTORE_PASS")
            }
        }
    }
    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.findByName("rel") ?: signingConfigs.getByName("debug")
        }
    }
    packaging {
        // the binaries are executed, so they must be extracted to nativeLibraryDir
        jniLibs.useLegacyPackaging = true
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}
