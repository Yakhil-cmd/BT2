# Q3254: external-file-url via if 3254

## Question
Can an unprivileged attacker entering through the embedded iframe render path in `if` (packages/gui/src/electron/utils/isValidURL.ts) control filename/path with traversal or extension mismatch with reordered RPC events and drive the sequence connect -> approve -> switch context -> execute so the GUI would open an unsafe scheme or local endpoint from untrusted metadata/notification content, violating the invariant that embedded content must not communicate authority to the app, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/utils/isValidURL.ts` / `if`
- Entrypoint: embedded iframe render path
- Attacker controls: filename/path with traversal or extension mismatch; with reordered RPC events
- Exploit idea: open an unsafe scheme or local endpoint from untrusted metadata/notification content
- Invariant to test: embedded content must not communicate authority to the app
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
