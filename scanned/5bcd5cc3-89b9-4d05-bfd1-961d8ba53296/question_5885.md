# Q5885: hostile JSON drives a security decision - (Extension).Owner in extension.go

## Question
Does `Owner` in [pkg/cmd/extension/extension.go](pkg/cmd/extension/extension.go#L182) unmarshal a response field that later gates a security decision (host, path, permission, verification result) without validating its shape or range?

## Target
- File/function: [pkg/cmd/extension/extension.go:182](pkg/cmd/extension/extension.go#L182) - `(Extension).Owner`
- Entrypoint: gh extension extension
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Return a crafted JSON body from an attacker-controlled host or an attacker-owned object.
- Invariant to test: Every response field used for a trust decision is validated against an allowlist before use.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test of hostile JSON payloads asserting rejection.
