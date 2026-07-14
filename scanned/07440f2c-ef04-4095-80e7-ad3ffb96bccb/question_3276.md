# Q3276: external-file-url via if 3276

## Question
Can an unprivileged attacker entering through the imported file parse path in `if` (packages/gui/src/electron/utils/sanitizeFilename.ts) control remote JSON changing between validation and use through a batch of rapid user-accessible actions and drive the sequence fetch -> cache -> refresh -> submit so the GUI would save or import a file under a misleading name or type that changes subsequent wallet action, violating the invariant that embedded content must not communicate authority to the app, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/utils/sanitizeFilename.ts` / `if`
- Entrypoint: imported file parse path
- Attacker controls: remote JSON changing between validation and use; through a batch of rapid user-accessible actions
- Exploit idea: save or import a file under a misleading name or type that changes subsequent wallet action
- Invariant to test: embedded content must not communicate authority to the app
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
