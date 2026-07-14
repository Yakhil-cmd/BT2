# Q116: external-file-url via WriteStreamPromise 116

## Question
Can an unprivileged attacker entering through the save/download action in `WriteStreamPromise` (packages/gui/src/electron/utils/downloadFile.ts) control filename/path with traversal or extension mismatch with case-normalized identifiers and drive the sequence validate input -> normalize payload -> call RPC so the GUI would open an unsafe scheme or local endpoint from untrusted metadata/notification content, violating the invariant that embedded content must not communicate authority to the app, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/utils/downloadFile.ts` / `WriteStreamPromise`
- Entrypoint: save/download action
- Attacker controls: filename/path with traversal or extension mismatch; with case-normalized identifiers
- Exploit idea: open an unsafe scheme or local endpoint from untrusted metadata/notification content
- Invariant to test: embedded content must not communicate authority to the app
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
