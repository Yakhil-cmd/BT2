# Q1408: external-file-url via if 1408

## Question
Can an unprivileged attacker entering through the embedded iframe render path in `if` (packages/gui/src/electron/utils/sanitizeFilename.ts) control filename/path with traversal or extension mismatch after a network switch and drive the sequence preview -> mutate controlled state -> confirm so the GUI would fetch private/local resources during normal GUI use, violating the invariant that download/import previews must match consumed bytes, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/utils/sanitizeFilename.ts` / `if`
- Entrypoint: embedded iframe render path
- Attacker controls: filename/path with traversal or extension mismatch; after a network switch
- Exploit idea: fetch private/local resources during normal GUI use
- Invariant to test: download/import previews must match consumed bytes
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
