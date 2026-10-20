# Building, formatting and signing

Install JDK 21 and Android SDK platform/build-tools 35. Set `JAVA_HOME` and `ANDROID_HOME`. The checked-in Gradle wrapper downloads its checksum-pinned distribution. Run:

```sh
./gradlew testDebugUnitTest lintDebug assembleDebug
```

Use `gradlew.bat` in PowerShell. No parent-directory toolchain or backend checkout is needed. `local.properties`, debug/release signing keys, `.gradle`, `build` and APK output are ignored by Git.

Java files follow google-java-format 1.24.0. Use its all-dependencies JAR with JDK 21:

```sh
java -jar /path/to/google-java-format-1.24.0-all-deps.jar --replace $(find app/src tools -name '*.java')
```

The formatter is a development tool, not an app dependency. Never reformat generated build files. CI runs unit tests/lint and builds a debug APK; CI artifacts do not have a stable production signing identity.

## Production signing

Use Android Studio's signed-APK flow or a private Gradle signing configuration to create a release build. Keep the keystore and passwords outside the repository and use the same certificate for upgrades. Do not put passwords or master keys in `build.gradle`, resources, BuildConfig or CI YAML. Preserve the package name if you need an upgrade of the same app.

Uninstalling or clearing storage removes interrupted-provisioning recovery records. Do not require users to uninstall during an incomplete operation. The repository does not distribute the original development machine's debug keystore or prebuilt APK.

To host a built artifact with the companion backend, copy the APK to that server's `dist/NFC-Tag-Writer-debug.apk`, or set its `APK_PATH` to the deployed APK. The download route does not require exposing a separate file-server port. Updating that file is a deployment action; the two source repositories remain independent.
