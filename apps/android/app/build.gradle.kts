plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.cyclonedx.bom")
}

// Release signing comes from the environment (CI secrets, or a throwaway
// self-signed key in CI when no secret is configured). Never commit a keystore.
val keystorePath: String? = System.getenv("SNOW_KEYSTORE")

android {
    namespace = "app.snowtalk.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "app.snowtalk.android"
        minSdk = 28
        targetSdk = 35
        versionCode = (System.getenv("SNOW_VERSION_CODE") ?: "1").toInt()
        versionName = System.getenv("SNOW_VERSION_NAME") ?: "0.1.0"
    }

    signingConfigs {
        if (keystorePath != null) {
            create("release") {
                storeFile = file(keystorePath)
                storePassword = System.getenv("SNOW_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("SNOW_KEY_ALIAS")
                keyPassword = System.getenv("SNOW_KEY_PASSWORD")
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            if (keystorePath != null) signingConfig = signingConfigs.getByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures { compose = true }
    // Reproducible-ish APKs: no build timestamps or VCS info baked in.
    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.9.3")
    // UniFFI bindings: JNA to load libsnow_core.so, coroutines for async calls.
    implementation("net.java.dev.jna:jna:5.15.0@aar")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
}
