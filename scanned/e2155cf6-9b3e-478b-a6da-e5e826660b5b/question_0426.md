# Q426: external-file-url via LinkAPI 426

## Question
Can an unprivileged attacker entering through the imported file parse path in `LinkAPI` (packages/gui/src/electron/constants/LinkAPI.ts) control remote JSON changing between validation and use with reordered RPC events and drive the sequence download or render content -> trigger linked wallet action so the GUI would save or import a file under a misleading name or type that changes subsequent wallet action, violating the invariant that embedded content must not communicate authority to the app, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/constants/LinkAPI.ts` / `LinkAPI`
- Entrypoint: imported file parse path
- Attacker controls: remote JSON changing between validation and use; with reordered RPC events
- Exploit idea: save or import a file under a misleading name or type that changes subsequent wallet action
- Invariant to test: embedded content must not communicate authority to the app
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
