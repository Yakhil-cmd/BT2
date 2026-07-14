# Q2524: external-file-url via useEnableFilePropagationServer 2524

## Question
Can an unprivileged attacker entering through the remote JSON fetch helper in `useEnableFilePropagationServer` (packages/gui/src/hooks/useEnableFilePropagationServer.ts) control filename/path with traversal or extension mismatch after a failed RPC response and drive the sequence select -> edit backing object -> submit so the GUI would open an unsafe scheme or local endpoint from untrusted metadata/notification content, violating the invariant that untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/hooks/useEnableFilePropagationServer.ts` / `useEnableFilePropagationServer`
- Entrypoint: remote JSON fetch helper
- Attacker controls: filename/path with traversal or extension mismatch; after a failed RPC response
- Exploit idea: open an unsafe scheme or local endpoint from untrusted metadata/notification content
- Invariant to test: untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
