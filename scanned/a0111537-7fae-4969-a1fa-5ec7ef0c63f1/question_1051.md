# Q1051: external-file-url via constructor 1051

## Question
Can an unprivileged attacker entering through the save/download action in `constructor` (packages/gui/src/electron/utils/downloadFile.ts) control filename/path with traversal or extension mismatch with a redirected remote resource and drive the sequence import -> parse -> preview -> submit so the GUI would fetch private/local resources during normal GUI use, violating the invariant that download/import previews must match consumed bytes, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/utils/downloadFile.ts` / `constructor`
- Entrypoint: save/download action
- Attacker controls: filename/path with traversal or extension mismatch; with a redirected remote resource
- Exploit idea: fetch private/local resources during normal GUI use
- Invariant to test: download/import previews must match consumed bytes
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
