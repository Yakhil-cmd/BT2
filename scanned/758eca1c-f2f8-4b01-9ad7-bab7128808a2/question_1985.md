# Q1985: external-file-url via write 1985

## Question
Can an unprivileged attacker entering through the imported file parse path in `write` (packages/gui/src/electron/utils/downloadFile.ts) control filename/path with traversal or extension mismatch during a pending modal confirmation and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would render embedded content with privileges that can trigger approvals, violating the invariant that untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/utils/downloadFile.ts` / `write`
- Entrypoint: imported file parse path
- Attacker controls: filename/path with traversal or extension mismatch; during a pending modal confirmation
- Exploit idea: render embedded content with privileges that can trigger approvals
- Invariant to test: untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
