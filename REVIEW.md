# Source review and repository split

Reviewed October 20, 2026. This review checks source, protocol vectors and simulated-card behavior. It is not a certification, independent cryptographic audit or substitute for phone/tag RF testing.

## Scope and changes

- Formatted all Java sources with google-java-format 1.24.0 and documented protocol-critical behavior.
- Made the Gradle project standalone, without references to a parent backend directory, machine-specific SDK, copied debug keystore or embedded master.
- Pinned the Gradle 8.11.1 distribution checksum.
- Added best-effort wiping of mutable session and per-tag working-key arrays on completion/failure; documented that JVM/UI/cipher copies prevent guaranteed full memory erasure.
- Invalidated sessions after failed plain file commands, where RF loss can make the command counter ambiguous; added regression tests.
- Bounded static NDEF reads/writes and prevented command-counter wrap; added pre-transport bounds tests.
- Cleared replaced pending operations and handled a reader callback racing a shut-down worker.
- Kept immutable in-flight operation ownership, journal-before-mutation behavior, exact NDEF offsets, strict response MAC verification and key-0-last provisioning.
- Reviewed the frozen-file access-byte checks and preserved the requirement that both write paths are denied before resuming an already frozen file.

## Important behavior

New writes authenticate every original key before mutation. Rewrite mode requires known old masters. Recovery binds the UID, old/new masters, modes, URL and lock choice through local fingerprint metadata. Only explicit authentication rejection triggers the alternative-key path; transport errors stop immediately.

Permanent locking remains off by default with explicit confirmation. File locks and discarded random management credentials are irreversible. A response loss after replacing key 0 can leave the app unable to prove completion or resume, even though the tag is already locked. Subsequent signature verification does not certify every lock setting. There is no reset/bypass for unknown keys or tamper history.

## Validation and residual risks

Gradle unit tests, lint and debug assembly exercise CMAC/NXP vectors, Go interoperability inputs, complete provisioning, both rewrite modes, interrupted key changes, journal failure, lock ordering/recovery and session invalidation. The source uses Android's NFC APIs and has no third-party runtime libraries. JUnit and formatting/build tools are development dependencies.

The app requires physical acceptance tests with each tag revision and phone/antenna combination. Do not infer authenticity of a physical item from a verified URL alone. Backend freshness is a separate policy. Protect master keys and tag attachment/seals; there is no supported ownership-transfer system. Do not uninstall or change signing identity during interrupted provisioning. Do not permanently lock production stock until the URL, backend key, mode, HTTPS trust and verification flow have been tested.

No deployment master, keystore, APK, local preferences or device history is published. Public known-answer fixture masters are intentionally nonsecret. The original running deployment and its installed APK are not replaced by this source review.
