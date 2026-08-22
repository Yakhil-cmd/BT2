# Q1954: hostile JSON drives a security decision - (Untrusted).UnmarshalJSON in untrusted.go

## Question
Does `UnmarshalJSON` in [pkg/iostreams/untrusted.go](pkg/iostreams/untrusted.go#L63) unmarshal a response field that later gates a security decision (host, path, permission, verification result) without validating its shape or range?

## Target
- File/function: [pkg/iostreams/untrusted.go:63](pkg/iostreams/untrusted.go#L63) - `(Untrusted).UnmarshalJSON`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Return a crafted JSON body from an attacker-controlled host or an attacker-owned object.
- Invariant to test: Every response field used for a trust decision is validated against an allowlist before use.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test of hostile JSON payloads asserting rejection.
