pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "wireguardrtc-android"
// :wgbridge-aar (gomobile-built) was dropped in its
// generated marshalling code triggered the alignment panic we
// chased through . :wgbridge-native-aar (cgo + //export)
// replaces it. The wgbridge/ Go module stays on disk as
// reference for what NOT to do; not part of the build any more.
include(":app", ":signalling", ":wgbridge-native-aar")
