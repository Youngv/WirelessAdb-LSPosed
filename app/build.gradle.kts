import java.io.File

plugins { id("com.android.application") }

android {
    namespace = "dev.wirelessadb.autostart"
    compileSdk = 36

    defaultConfig {
        applicationId = "dev.wirelessadb.autostart"
        minSdk = 28
        targetSdk = 36
        versionCode = 20
        versionName = "1.1.0"
    }

    val keystorePath = System.getenv("SIGNING_STORE_FILE")
    val hasCustomKeystore = !keystorePath.isNullOrBlank() && File(keystorePath).exists()

    signingConfigs {
        if (hasCustomKeystore) {
            create("customRelease") {
                storeFile = File(keystorePath!!)
                storePassword = System.getenv("SIGNING_STORE_PASSWORD")
                keyAlias = System.getenv("SIGNING_KEY_ALIAS")
                keyPassword = System.getenv("SIGNING_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = if (hasCustomKeystore) {
                signingConfigs.getByName("customRelease")
            } else {
                signingConfigs.getByName("debug")
            }
        }
    }
}

dependencies { compileOnly("de.robv.android.xposed:api:82") }
