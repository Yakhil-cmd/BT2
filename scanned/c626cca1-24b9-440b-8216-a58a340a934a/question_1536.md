# Q1536: external-file-url via handleOpen 1536

## Question
Can an unprivileged attacker entering through the save/download action in `handleOpen` (packages/core/src/hooks/useOpenExternal.ts) control filename/path with traversal or extension mismatch with a delayed metadata fetch and drive the sequence load persisted state -> render approval -> execute command so the GUI would parse file content differently from what the confirmation displays, violating the invariant that embedded content must not communicate authority to the app, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/core/src/hooks/useOpenExternal.ts` / `handleOpen`
- Entrypoint: save/download action
- Attacker controls: filename/path with traversal or extension mismatch; with a delayed metadata fetch
- Exploit idea: parse file content differently from what the confirmation displays
- Invariant to test: embedded content must not communicate authority to the app
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
