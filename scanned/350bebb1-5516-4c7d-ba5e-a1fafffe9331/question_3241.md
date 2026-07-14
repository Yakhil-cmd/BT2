# Q3241: external-file-url via canReadFile 3241

## Question
Can an unprivileged attacker entering through the imported file parse path in `canReadFile` (packages/gui/src/electron/utils/canReadFile.ts) control filename/path with traversal or extension mismatch with reordered RPC events and drive the sequence preview -> mutate controlled state -> confirm so the GUI would parse file content differently from what the confirmation displays, violating the invariant that download/import previews must match consumed bytes, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/utils/canReadFile.ts` / `canReadFile`
- Entrypoint: imported file parse path
- Attacker controls: filename/path with traversal or extension mismatch; with reordered RPC events
- Exploit idea: parse file content differently from what the confirmation displays
- Invariant to test: download/import previews must match consumed bytes
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
