# Q474: external-file-url via sanitizeFilename 474

## Question
Can an unprivileged attacker entering through the remote JSON fetch helper in `sanitizeFilename` (packages/gui/src/electron/utils/sanitizeFilename.ts) control remote JSON changing between validation and use with a redirected remote resource and drive the sequence connect -> approve -> switch context -> execute so the GUI would open an unsafe scheme or local endpoint from untrusted metadata/notification content, violating the invariant that download/import previews must match consumed bytes, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/utils/sanitizeFilename.ts` / `sanitizeFilename`
- Entrypoint: remote JSON fetch helper
- Attacker controls: remote JSON changing between validation and use; with a redirected remote resource
- Exploit idea: open an unsafe scheme or local endpoint from untrusted metadata/notification content
- Invariant to test: download/import previews must match consumed bytes
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
