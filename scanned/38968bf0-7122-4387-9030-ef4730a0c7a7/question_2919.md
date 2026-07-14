# Q2919: external-file-url via promise 2919

## Question
Can an unprivileged attacker entering through the external link click in `promise` (packages/gui/src/electron/utils/downloadFile.ts) control iframe content with navigation or message attempts with hidden Unicode characters and drive the sequence import -> parse -> preview -> submit so the GUI would open an unsafe scheme or local endpoint from untrusted metadata/notification content, violating the invariant that untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/utils/downloadFile.ts` / `promise`
- Entrypoint: external link click
- Attacker controls: iframe content with navigation or message attempts; with hidden Unicode characters
- Exploit idea: open an unsafe scheme or local endpoint from untrusted metadata/notification content
- Invariant to test: untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
