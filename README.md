# NFC Tag Writer for Android

An Android application for provisioning **NXP NTAG 424 DNA TagTamper** tags with an HTTPS verification URL, encrypted tamper status and diversified AES keys. It works with [NFC SDM Backend for Go](https://github.com/v0rtal/nfc-sdm-backend-go), but contains no embedded backend key and does not need that repository to build.

Requires **Android 8.0+**, NFC hardware, ISO-DEP support and a supported TagTamper tag. The app implements AES EV2First authentication and secure messaging directly through Android's NFC transport. It has **no Internet permission**: keys and offline verification stay on the phone. Opening a verified URL launches the user's browser separately.

## What it does

- Writes a Type 4 NDEF HTTPS URL ending in `/tagtt` or `/api/tagtt`.
- Programs an encrypted PICC/UID/read-counter field, encrypted file data containing tamper status, and a truncated CMAC.
- Derives all five AES tag keys from a 16- or 32-byte backend master, using `legacy` or `standard` mode to match the server.
- Checks all existing keys and management permissions before any provisioning write.
- Rewrites compatible unlocked tags when their existing master and derivation mode are known.
- Records recovery checkpoints and resumes interrupted writes with the same UID and configuration.
- Reads a second tap and verifies the AES signature and tamper status locally, without contacting a server.
- Optionally applies an explicitly confirmed **permanent lock** after verifying the written URL.

This app does not maintain the backend inventory, transfer ownership, reset a tamper history or recover unknown tag keys. LRP switching, Random ID tags, other NFC chip families and arbitrary raw per-tag key entry are not supported.

## Build and install

Use Android Studio or a JDK 21 installation with Android SDK 35. Java source compatibility is 17; the wrapper uses Gradle 8.11.1 with a pinned distribution SHA-256 and Android Gradle Plugin 8.9.2.

```sh
git clone https://github.com/v0rtal/nfc-tag-writer-android.git
cd nfc-tag-writer-android
chmod +x gradlew
./gradlew testDebugUnitTest lintDebug assembleDebug
```

On Windows, use `gradlew.bat`. Configure `ANDROID_HOME`/`ANDROID_SDK_ROOT`, or create an ignored `local.properties` containing your SDK path. `JAVA_HOME` must point to your local JDK. The project does not include a JDK, SDK, build cache or signing key.

The installable output is `app/build/outputs/apk/debug/app-debug.apk`. Debug artifacts from CI are development builds, not signed production releases. To update an installed app while retaining recovery records, use the **same signing certificate**. Do not uninstall/clear storage during interrupted setup. For distribution, create and protect a release keystore outside Git; see [release and signing](docs/BUILDING.md).

## Provision a tag

1. Start the backend with a saved nonzero master and the chosen derivation mode. Provide a reachable HTTPS `/tagtt` or `/api/tagtt` URL. Public browsers need a trusted TLS certificate; a private self-signed certificate must be trusted separately.
2. Enter that URL, the **new** backend master in hex, and its mode. The writer refuses the factory all-zero master for new provisioning. The original NFC Developer App workflow normally uses `legacy`; `standard` is the upstream backend's newer diversification, not universal compatibility with all tools.
3. For a fresh tag, leave **Rewrite an unlocked tag** unchecked. To rewrite a compatible tag, select it and enter the **old** backend master and old mode. Backend masters are different from raw per-tag AES key values.
4. Keep the physical tamper loop **closed**. Tap **Write tag**, read the confirmation and scan the tag. Hold it at the NFC antenna until setup completes.
5. Remove the tag. Tap **Verify tag** and scan again. The app verifies locally and displays UID, counter and tamper state. **Open verified URL** opens the browser for server verification/inventory recording.

The app remembers the endpoint and derivation mode, not the raw masters. It disables screenshots, view-state saving, autofill and backups for secret fields. Mutable operation/session arrays are cleared where practical; Java strings, Android widgets and cipher internals prevent a guarantee that all process-memory copies are erased immediately.

## Interrupted setup and rewriting

Tag provisioning is a sequence of NFC commands, not an atomic transaction. A failed response may mean a command was accepted before the RF link dropped. Keep the **same URL, old/new masters, old/new modes and lock choice**, select **Resume an interrupted setup from this app**, and scan the same UID. The writer checks its local configuration fingerprint and tests the intended or original key for every slot before resuming.

Recovery data stores UID, URL, stage and a SHA-256 fingerprint, not a recoverable master secret. The fingerprint includes the masters, so protect app storage and use high-entropy masters. Transport errors stop the operation; they are not treated as a reason to try arbitrary alternative keys. The app cannot rewrite preconfigured tags with unknown credentials or incompatible access settings.

## Permanent locking

**Permanently lock after writing is off by default.** It adds an irreversible-action warning to confirmation. The writer verifies the dynamic URL's destination, signature and UID before locking. It does not prove that the public backend is reachable or that its certificate will be trusted later; test your deployment first.

Locking denies Write, ReadWrite and Change access on all three files, preserving reads and SDM settings. It replaces management key 0 with a random key, authenticates once and discards that credential without saving it. Keys 1–4 remain unchanged for message verification. This is irreversible file access denial and credential destruction, **not an OTP hardware fuse**.

After success, even your saved backend master cannot change the tag's URL, settings or keys. An interrupted lock may be partial. Resume can finish while management key 0 is still available; after its random replacement reaches the tag, management recovery is impossible even if the app misses the response. A later Verify checks the signature, not every lock setting.

Enabling TagTamper itself is permanent. Once an open loop is recorded, closing it again does not remove the tamper history. Use spare hardware for acceptance testing. Simulated-card tests and NXP vectors are not an independent hardware security audit.

## Development and protocol

See [architecture and protocol](docs/PROTOCOL.md), [build/signing](docs/BUILDING.md), [review notes](REVIEW.md) and [security](SECURITY.md). Core tests cover RFC CMAC, NXP authentication/secure-command examples, shared Go/Java vectors, migration in both modes, failures after each key change, permanent locking and partial-lock recovery. No Android emulator can substitute for phone/tag RF testing.

`tools/GenerateInteropVectors.java` generates deterministic public compatibility fixtures. Its master values are **published test data, not deployment secrets**. See the backend's `testdata/android-sdm.json` for matching inputs. No source code is shared through relative paths between repositories.

MIT licensed with upstream notices preserved; Gradle wrapper distribution files retain their separate Apache-2.0 notice in `gradle/WRAPPER-LICENSE.txt`. See [NOTICE](NOTICE.md). This project is not affiliated with NXP or NFC Developer App.
