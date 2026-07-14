# Q2731: external-file-url via isValidURL 2731

## Question
Can an unprivileged attacker entering through the save/download action in `isValidURL` (packages/core/src/utils/isValidURL.ts) control URL with encoded scheme, redirects, localhost/private targets, or Unicode host confusion after a failed RPC response and drive the sequence preview -> mutate controlled state -> confirm so the GUI would render embedded content with privileges that can trigger approvals, violating the invariant that embedded content must not communicate authority to the app, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/core/src/utils/isValidURL.ts` / `isValidURL`
- Entrypoint: save/download action
- Attacker controls: URL with encoded scheme, redirects, localhost/private targets, or Unicode host confusion; after a failed RPC response
- Exploit idea: render embedded content with privileges that can trigger approvals
- Invariant to test: embedded content must not communicate authority to the app
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
