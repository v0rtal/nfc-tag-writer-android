# Security

Never publish deployment masters, per-tag keys, keystores, device provisioning journals or live signed tag URLs in issues. Public test masters are known-answer data and must not be used on deployed tags.

The app provisions hardware through irreversible command sequences. Tamper activation and optional permanent locking cannot be undone. A lost NFC response may follow an accepted write. Read README and docs/PROTOCOL.md; protect recovery records and use spare hardware for acceptance tests.

Local signature verification is separate from server replay detection and does not prove ownership or the physical item's origin. Java/Android memory cleanup is best-effort, not guaranteed erasure of all UI/JVM/cipher copies.

Use GitHub private vulnerability reporting if enabled. Otherwise request a private channel without including secrets or exploitable details in a public issue. No security certification, production readiness guarantee or response-time SLA is claimed.
