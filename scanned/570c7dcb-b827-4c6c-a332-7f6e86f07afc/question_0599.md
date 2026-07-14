# Q599: external-file-url via StyledIframe 599

## Question
Can an unprivileged attacker entering through the save/download action in `StyledIframe` (packages/core/src/components/SandboxedIframe/SandboxedIframe.tsx) control filename/path with traversal or extension mismatch with a duplicate identifier and drive the sequence load persisted state -> render approval -> execute command so the GUI would render embedded content with privileges that can trigger approvals, violating the invariant that embedded content must not communicate authority to the app, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/core/src/components/SandboxedIframe/SandboxedIframe.tsx` / `StyledIframe`
- Entrypoint: save/download action
- Attacker controls: filename/path with traversal or extension mismatch; with a duplicate identifier
- Exploit idea: render embedded content with privileges that can trigger approvals
- Invariant to test: embedded content must not communicate authority to the app
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
