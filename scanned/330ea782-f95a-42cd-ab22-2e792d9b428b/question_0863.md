# Q863: external-file-url via isValidURL 863

## Question
Can an unprivileged attacker entering through the remote JSON fetch helper in `isValidURL` (packages/core/src/utils/isValidURL.ts) control oversized or polyglot import file during a pending modal confirmation and drive the sequence validate input -> normalize payload -> call RPC so the GUI would parse file content differently from what the confirmation displays, violating the invariant that embedded content must not communicate authority to the app, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/core/src/utils/isValidURL.ts` / `isValidURL`
- Entrypoint: remote JSON fetch helper
- Attacker controls: oversized or polyglot import file; during a pending modal confirmation
- Exploit idea: parse file content differently from what the confirmation displays
- Invariant to test: embedded content must not communicate authority to the app
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
