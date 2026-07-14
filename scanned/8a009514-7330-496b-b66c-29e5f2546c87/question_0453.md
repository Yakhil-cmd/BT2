# Q453: external-file-url via isValidURL 453

## Question
Can an unprivileged attacker entering through the save/download action in `isValidURL` (packages/gui/src/electron/utils/isValidURL.ts) control URL with encoded scheme, redirects, localhost/private targets, or Unicode host confusion with a duplicate identifier and drive the sequence select -> edit backing object -> submit so the GUI would open an unsafe scheme or local endpoint from untrusted metadata/notification content, violating the invariant that download/import previews must match consumed bytes, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/utils/isValidURL.ts` / `isValidURL`
- Entrypoint: save/download action
- Attacker controls: URL with encoded scheme, redirects, localhost/private targets, or Unicode host confusion; with a duplicate identifier
- Exploit idea: open an unsafe scheme or local endpoint from untrusted metadata/notification content
- Invariant to test: download/import previews must match consumed bytes
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
