# Q2563: external-file-url via getFileExtension 2563

## Question
Can an unprivileged attacker entering through the embedded iframe render path in `getFileExtension` (packages/gui/src/util/getFileExtension.ts) control URL with encoded scheme, redirects, localhost/private targets, or Unicode host confusion after a profile switch and drive the sequence fetch -> cache -> refresh -> submit so the GUI would render embedded content with privileges that can trigger approvals, violating the invariant that embedded content must not communicate authority to the app, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/util/getFileExtension.ts` / `getFileExtension`
- Entrypoint: embedded iframe render path
- Attacker controls: URL with encoded scheme, redirects, localhost/private targets, or Unicode host confusion; after a profile switch
- Exploit idea: render embedded content with privileges that can trigger approvals
- Invariant to test: embedded content must not communicate authority to the app
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
