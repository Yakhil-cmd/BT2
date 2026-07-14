# Q1612: external-file-url via handleOpen 1612

## Question
Can an unprivileged attacker entering through the save/download action in `handleOpen` (packages/gui/src/hooks/useOpenExternal.ts) control oversized or polyglot import file after canceling and reopening the dialog and drive the sequence fetch -> cache -> refresh -> submit so the GUI would render embedded content with privileges that can trigger approvals, violating the invariant that untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/hooks/useOpenExternal.ts` / `handleOpen`
- Entrypoint: save/download action
- Attacker controls: oversized or polyglot import file; after canceling and reopening the dialog
- Exploit idea: render embedded content with privileges that can trigger approvals
- Invariant to test: untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
