# Q465: external-file-url via openExternal 465

## Question
Can an unprivileged attacker entering through the imported file parse path in `openExternal` (packages/gui/src/electron/utils/openExternal.ts) control filename/path with traversal or extension mismatch with case-normalized identifiers and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would parse file content differently from what the confirmation displays, violating the invariant that untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/utils/openExternal.ts` / `openExternal`
- Entrypoint: imported file parse path
- Attacker controls: filename/path with traversal or extension mismatch; with case-normalized identifiers
- Exploit idea: parse file content differently from what the confirmation displays
- Invariant to test: untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
