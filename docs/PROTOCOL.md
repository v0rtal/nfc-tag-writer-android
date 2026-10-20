# Provisioning and protocol

## Code map

- `MainActivity`: UI, NFC reader lifecycle, immutable operation snapshots, a single worker, recovery metadata and explicit write/lock consent.
- `Bytes`: binary/hex helpers and little-endian fields.
- `Crypto`: AES-CBC, padding, RFC 4493 CMAC, truncated odd-byte CMAC, session vectors, CRC and backend-compatible diversification.
- `TagSession`: ISO application selection, chained GetVersion, EV2First challenge/response, transaction ID, command counters and secure-command/response MACs.
- `TagTemplate`: exact serialized Type 4 NDEF file and offsets.
- `Provisioner`: tag/capability/key preflight, journal-before-write checkpoints, readback, key migration and final authentication.
- `SunVerifier`: offline encrypted PICC/file parsing and signature verification.
- `TagLocker`: preflight every file, irreversible access denial, management-key replacement and best-effort credential cleanup.

## Provisioning order

Select application DF name `D2760000850101`, validate the TagTamper GetVersion identifiers, and obtain a stable seven-byte UID. Authenticate slots 0–4 with factory keys for a fresh tag or keys derived from the supplied old master. Recovery first tries intended new keys, falling back to original keys only after an authentication-rejection status. Never infer a key from its version byte.

Authenticate management key 0 and compare the authenticated UID. Save a recovery checkpoint before mutations. Disable mirroring, clear NLEN, write body chunks, read back static data, then restore NLEN. Change keys 1–4, configure/read back SDM, enable TagTamper, and change key 0 last. Reauthenticate every intended key before reporting completion. Optional lock starts only after independent dynamic-URL verification.

## NDEF and SDM

File 02 / ISO E104 is 256 bytes. The writer creates one short URI record with HTTPS prefix `04`. All offsets include the two-byte NLEN and refer to the serialized bytes, not the visible URL string.

```text
https://example.com/tagtt?picc_data=<32 hex>&enc=<32 hex>&cmac=<16 hex>
```

The ASCII SDM options are `D9`: UID, read counter, encrypted file data and tamper status. Normal provisioning uses public reads and management-key-0 writes/RW/settings. Meta-read key is 1, file-read key is 2 and authenticated counter retrieval key is 0. The encrypted placeholder starts with tamper status and expands one encrypted block into 32 hexadecimal characters. MAC input starts at the encrypted data and includes `&cmac=`. Changing URL serialization, compression or parameter names without recomputing offsets breaks verification.

## Authentication/session rules

EV2First (`71` / continuation `AF`) proves both random challenges, captures TI, validates supported capabilities, and derives encryption/MAC session keys. Command MACs bind the instruction, command counter, TI, clear header and encrypted payload. Response MAC verification precedes decryption/use. Changing the active management key drops the session and returns a distinct empty success response. A plain file-command error invalidates the local session because command-counter agreement may be lost. Session counters must not wrap.

## State and limits

Only AES provisioning is implemented. LRP tags, Random ID tags and unrelated NFC families are refused. File and capability support is intentionally narrower than the full datasheet. Secrets remain local; opening the verified URL is the only browser handoff. Verification does not assert freshness: the companion backend makes replay/counter decisions.

References: [NXP TagTamper datasheet](https://www.nxp.com/docs/en/data-sheet/NT4H2421Tx.pdf), [NXP AN12196](https://www.nxp.com/docs/en/application-note/AN12196.pdf), and the upstream backend's derivation scheme. Consult the exact tag revision before production provisioning.
