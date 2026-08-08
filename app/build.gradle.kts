plugins {
    id("com.android.application")
}

android {
    namespace = "mfsx.xposed.trustmealready"
    compileSdk = 34
    buildToolsVersion = "34.0.0"

    defaultConfig {
        applicationId = "mfsx.xposed.trustmealready"
        // Android 5.0 (API 21) - Android 16 (API 36)
        minSdk = 21
        targetSdk = 34
        versionCode = 9
        versionName = "2.7.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    buildFeatures {
        resValues = true
    }

    packaging {
        jniLibs {
            // Extract .so files at install time so FridaController can
            // load libtma.so via System.load() from the module's lib dir
            useLegacyPackaging = true
        }
    }
}

dependencies {
    compileOnly("de.robv.android.xposed:api:82")
    // Pure Java XZ decompression - used by FridaController to decompress frida-gadget.so.xz at runtime
    implementation("org.tukaani:xz:1.10")
}
