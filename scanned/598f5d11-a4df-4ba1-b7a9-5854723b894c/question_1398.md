# Q1398: external-file-url via openExternal 1398

## Question
Can an unprivileged attacker entering through the remote JSON fetch helper in `openExternal` (packages/gui/src/electron/utils/openExternal.ts) control oversized or polyglot import file with a redirected remote resource and drive the sequence download or render content -> trigger linked wallet action so the GUI would save or import a file under a misleading name or type that changes subsequent wallet action, violating the invariant that embedded content must not communicate authority to the app, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/utils/openExternal.ts` / `openExternal`
- Entrypoint: remote JSON fetch helper
- Attacker controls: oversized or polyglot import file; with a redirected remote resource
- Exploit idea: save or import a file under a misleading name or type that changes subsequent wallet action
- Invariant to test: embedded content must not communicate authority to the app
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
