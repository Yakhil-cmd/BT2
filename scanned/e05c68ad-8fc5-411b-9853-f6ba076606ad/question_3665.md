# Q3665: external-file-url via isValidURL 3665

## Question
Can an unprivileged attacker entering through the imported file parse path in `isValidURL` (packages/core/src/utils/isValidURL.ts) control filename/path with traversal or extension mismatch after a network switch and drive the sequence import -> parse -> preview -> submit so the GUI would parse file content differently from what the confirmation displays, violating the invariant that download/import previews must match consumed bytes, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/core/src/utils/isValidURL.ts` / `isValidURL`
- Entrypoint: imported file parse path
- Attacker controls: filename/path with traversal or extension mismatch; after a network switch
- Exploit idea: parse file content differently from what the confirmation displays
- Invariant to test: download/import previews must match consumed bytes
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
