# Q3853: external-file-url via close 3853

## Question
Can an unprivileged attacker entering through the remote JSON fetch helper in `close` (packages/gui/src/electron/utils/downloadFile.ts) control iframe content with navigation or message attempts after a failed RPC response and drive the sequence import -> parse -> preview -> submit so the GUI would fetch private/local resources during normal GUI use, violating the invariant that untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/utils/downloadFile.ts` / `close`
- Entrypoint: remote JSON fetch helper
- Attacker controls: iframe content with navigation or message attempts; after a failed RPC response
- Exploit idea: fetch private/local resources during normal GUI use
- Invariant to test: untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
