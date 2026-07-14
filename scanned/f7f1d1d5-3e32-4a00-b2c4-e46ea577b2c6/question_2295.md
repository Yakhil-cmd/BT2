# Q2295: external-file-url via LinkAPI 2295

## Question
Can an unprivileged attacker entering through the external link click in `LinkAPI` (packages/gui/src/electron/constants/LinkAPI.ts) control filename/path with traversal or extension mismatch with a redirected remote resource and drive the sequence fetch -> cache -> refresh -> submit so the GUI would parse file content differently from what the confirmation displays, violating the invariant that embedded content must not communicate authority to the app, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/gui/src/electron/constants/LinkAPI.ts` / `LinkAPI`
- Entrypoint: external link click
- Attacker controls: filename/path with traversal or extension mismatch; with a redirected remote resource
- Exploit idea: parse file content differently from what the confirmation displays
- Invariant to test: embedded content must not communicate authority to the app
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
