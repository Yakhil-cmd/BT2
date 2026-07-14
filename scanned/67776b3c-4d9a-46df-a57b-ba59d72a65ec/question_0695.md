# Q695: external-file-url via getFileExtension 695

## Question
Can an unprivileged attacker entering through the external link click in `getFileExtension` (packages/gui/src/util/getFileExtension.ts) control oversized or polyglot import file with hidden Unicode characters and drive the sequence download or render content -> trigger linked wallet action so the GUI would parse file content differently from what the confirmation displays, violating the invariant that embedded content must not communicate authority to the app, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/util/getFileExtension.ts` / `getFileExtension`
- Entrypoint: external link click
- Attacker controls: oversized or polyglot import file; with hidden Unicode characters
- Exploit idea: parse file content differently from what the confirmation displays
- Invariant to test: embedded content must not communicate authority to the app
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
