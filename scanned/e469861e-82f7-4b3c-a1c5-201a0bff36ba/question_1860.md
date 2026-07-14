# Q1860: external-file-url via index 1860

## Question
Can an unprivileged attacker entering through the save/download action in `index` (packages/core/src/components/SandboxedIframe/index.ts) control iframe content with navigation or message attempts with a redirected remote resource and drive the sequence load persisted state -> render approval -> execute command so the GUI would parse file content differently from what the confirmation displays, violating the invariant that untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action, leading to High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact?

## Target
- File/function: `packages/core/src/components/SandboxedIframe/index.ts` / `index`
- Entrypoint: save/download action
- Attacker controls: iframe content with navigation or message attempts; with a redirected remote resource
- Exploit idea: parse file content differently from what the confirmation displays
- Invariant to test: untrusted URLs/files must be canonicalized once and constrained to safe schemes, paths, sizes, and displayed content before any wallet-impacting action
- Expected Immunefi impact: High: unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content causing direct wallet security impact
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
