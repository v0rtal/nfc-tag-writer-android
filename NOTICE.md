# Attribution

The app implements AES/EV2First and TagTamper provisioning from NXP protocol documentation, with backend key derivation compatible with [nfc-developer/sdm-backend](https://github.com/nfc-developer/sdm-backend). The original upstream MIT notice is retained in LICENSE. The Go backend is maintained separately at [v0rtal/nfc-sdm-backend-go](https://github.com/v0rtal/nfc-sdm-backend-go).

Gradle wrapper scripts were originally obtained from the Android example in [johnnyb/ntag424-java](https://github.com/johnnyb/ntag424-java) during development. The wrapper JAR is from the official Gradle 8.11.1 source. The wrapper is Apache-2.0 licensed; its notice is retained at `gradle/WRAPPER-LICENSE.txt`. Tag-protocol implementation classes from that project are not bundled as a runtime library.

NXP datasheet/AN12196 examples and public cryptographic test vectors are used for interoperability testing. Android, Gradle, JUnit and development tools retain their respective upstream licenses. The application has no third-party runtime library dependencies and no affiliation with NXP or NFC Developer App.
