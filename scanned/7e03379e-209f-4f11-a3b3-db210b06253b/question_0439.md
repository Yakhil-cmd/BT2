# Q439: external-file-url via canReadFile 439

## Question
Can an unprivileged attacker entering through the remote JSON fetch helper in `canReadFile` (packages/gui/src/electron/utils/canReadFile.ts) control oversized or polyglot import file with a delayed metadata fetch and drive the sequence select -> edit backing object -> submit so the GUI would render embedded content with privileges that can trigger approvals, violating the invariant that embedded content must not communicate authority to the app, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/utils/canReadFile.ts` / `canReadFile`
- Entrypoint: remote JSON fetch helper
- Attacker controls: oversized or polyglot import file; with a delayed metadata fetch
- Exploit idea: render embedded content with privileges that can trigger approvals
- Invariant to test: embedded content must not communicate authority to the app
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
