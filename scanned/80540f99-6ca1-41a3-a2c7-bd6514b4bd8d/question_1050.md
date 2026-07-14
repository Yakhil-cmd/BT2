# Q1050: external-file-url via constructor 1050

## Question
Can an unprivileged attacker entering through the imported file parse path in `constructor` (packages/gui/src/electron/utils/downloadFile.ts) control URL with encoded scheme, redirects, localhost/private targets, or Unicode host confusion with a redirected remote resource and drive the sequence import -> parse -> preview -> submit so the GUI would save or import a file under a misleading name or type that changes subsequent wallet action, violating the invariant that embedded content must not communicate authority to the app, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/utils/downloadFile.ts` / `constructor`
- Entrypoint: imported file parse path
- Attacker controls: URL with encoded scheme, redirects, localhost/private targets, or Unicode host confusion; with a redirected remote resource
- Exploit idea: save or import a file under a misleading name or type that changes subsequent wallet action
- Invariant to test: embedded content must not communicate authority to the app
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
