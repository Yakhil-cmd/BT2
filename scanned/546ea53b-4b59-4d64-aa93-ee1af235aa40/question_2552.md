# Q2552: external-file-url via useSaveFile 2552

## Question
Can an unprivileged attacker entering through the embedded iframe render path in `useSaveFile` (packages/gui/src/hooks/useSaveFile.ts) control filename/path with traversal or extension mismatch through a batch of rapid user-accessible actions and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would fetch private/local resources during normal GUI use, violating the invariant that untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/hooks/useSaveFile.ts` / `useSaveFile`
- Entrypoint: embedded iframe render path
- Attacker controls: filename/path with traversal or extension mismatch; through a batch of rapid user-accessible actions
- Exploit idea: fetch private/local resources during normal GUI use
- Invariant to test: untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
