# Q3277: external-file-url via if 3277

## Question
Can an unprivileged attacker entering through the save/download action in `if` (packages/gui/src/electron/utils/sanitizeFilename.ts) control iframe content with navigation or message attempts through a batch of rapid user-accessible actions and drive the sequence select -> edit backing object -> submit so the GUI would save or import a file under a misleading name or type that changes subsequent wallet action, violating the invariant that download/import previews must match consumed bytes, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/utils/sanitizeFilename.ts` / `if`
- Entrypoint: save/download action
- Attacker controls: iframe content with navigation or message attempts; through a batch of rapid user-accessible actions
- Exploit idea: save or import a file under a misleading name or type that changes subsequent wallet action
- Invariant to test: download/import previews must match consumed bytes
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
