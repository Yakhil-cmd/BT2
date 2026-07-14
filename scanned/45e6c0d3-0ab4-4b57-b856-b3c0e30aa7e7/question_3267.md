# Q3267: external-file-url via openExternal 3267

## Question
Can an unprivileged attacker entering through the embedded iframe render path in `openExternal` (packages/gui/src/electron/utils/openExternal.ts) control URL with encoded scheme, redirects, localhost/private targets, or Unicode host confusion with precision-boundary values and drive the sequence fetch -> cache -> refresh -> submit so the GUI would open an unsafe scheme or local endpoint from untrusted metadata/notification content, violating the invariant that embedded content must not communicate authority to the app, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/utils/openExternal.ts` / `openExternal`
- Entrypoint: embedded iframe render path
- Attacker controls: URL with encoded scheme, redirects, localhost/private targets, or Unicode host confusion; with precision-boundary values
- Exploit idea: open an unsafe scheme or local endpoint from untrusted metadata/notification content
- Invariant to test: embedded content must not communicate authority to the app
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
