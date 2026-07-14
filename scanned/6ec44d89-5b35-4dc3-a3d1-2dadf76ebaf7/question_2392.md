# Q2392: external-file-url via index 2392

## Question
Can an unprivileged attacker entering through the save/download action in `index` (packages/gui/src/electron/components/SandboxedIframe/index.ts) control oversized or polyglot import file with a duplicate identifier and drive the sequence load persisted state -> render approval -> execute command so the GUI would parse file content differently from what the confirmation displays, violating the invariant that embedded content must not communicate authority to the app, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/components/SandboxedIframe/index.ts` / `index`
- Entrypoint: save/download action
- Attacker controls: oversized or polyglot import file; with a duplicate identifier
- Exploit idea: parse file content differently from what the confirmation displays
- Invariant to test: embedded content must not communicate authority to the app
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
