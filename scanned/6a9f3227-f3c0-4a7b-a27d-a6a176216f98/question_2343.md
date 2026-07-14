# Q2343: external-file-url via sanitizeFilename 2343

## Question
Can an unprivileged attacker entering through the embedded iframe render path in `sanitizeFilename` (packages/gui/src/electron/utils/sanitizeFilename.ts) control filename/path with traversal or extension mismatch with precision-boundary values and drive the sequence validate input -> normalize payload -> call RPC so the GUI would parse file content differently from what the confirmation displays, violating the invariant that download/import previews must match consumed bytes, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/utils/sanitizeFilename.ts` / `sanitizeFilename`
- Entrypoint: embedded iframe render path
- Attacker controls: filename/path with traversal or extension mismatch; with precision-boundary values
- Exploit idea: parse file content differently from what the confirmation displays
- Invariant to test: download/import previews must match consumed bytes
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
