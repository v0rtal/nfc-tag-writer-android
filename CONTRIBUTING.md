# Contributing

Use JDK 21, SDK 35 and the checked-in Gradle wrapper. Format Java with google-java-format 1.24.0, then run `./gradlew testDebugUnitTest lintDebug assembleDebug` (`gradlew.bat` on Windows).

Document protocol invariants where they matter: byte offsets include NLEN, secure counters cannot wrap, response MACs precede decryption/use, and an RF error can follow an accepted write. Never fall back to another key after an arbitrary transport failure. Maintain journal-before-write ordering and explicit permanent-lock confirmation.

Add NXP/public known-answer or simulated-card failure tests for protocol changes. Unit tests do not replace hardware acceptance testing. Cross-check the companion Go backend fixture when changing derivation or serialization.

Do not commit masters, real tag keys, device journals, local SDK paths, keystores or APKs. Never remove a recovery record or require an uninstall while an operation may be incomplete. Explain any signing identity or data-format changes in the pull request. Use SECURITY.md for sensitive issues.
