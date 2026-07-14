# Q3401: external-file-url via srcDocHTML 3401

## Question
Can an unprivileged attacker entering through the remote JSON fetch helper in `srcDocHTML` (packages/core/src/components/SandboxedIframe/SandboxedIframe.tsx) control remote JSON changing between validation and use with a delayed metadata fetch and drive the sequence import -> parse -> preview -> submit so the GUI would parse file content differently from what the confirmation displays, violating the invariant that untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/core/src/components/SandboxedIframe/SandboxedIframe.tsx` / `srcDocHTML`
- Entrypoint: remote JSON fetch helper
- Attacker controls: remote JSON changing between validation and use; with a delayed metadata fetch
- Exploit idea: parse file content differently from what the confirmation displays
- Invariant to test: untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
