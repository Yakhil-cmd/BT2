# Q1409: external-file-url via if 1409

## Question
Can an unprivileged attacker entering through the remote JSON fetch helper in `if` (packages/gui/src/electron/utils/sanitizeFilename.ts) control filename/path with traversal or extension mismatch during a pending modal confirmation and drive the sequence preview -> mutate controlled state -> confirm so the GUI would fetch private/local resources during normal GUI use, violating the invariant that download/import previews must match consumed bytes, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/utils/sanitizeFilename.ts` / `if`
- Entrypoint: remote JSON fetch helper
- Attacker controls: filename/path with traversal or extension mismatch; during a pending modal confirmation
- Exploit idea: fetch private/local resources during normal GUI use
- Invariant to test: download/import previews must match consumed bytes
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
