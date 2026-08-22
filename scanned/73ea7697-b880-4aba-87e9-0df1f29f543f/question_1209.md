# Q1209: hostile JSON drives a security decision - stepLogFilenameRegexp in logs.go

## Question
Does `stepLogFilenameRegexp` in [pkg/cmd/run/view/logs.go](pkg/cmd/run/view/logs.go#L280) unmarshal a response field that later gates a security decision (host, path, permission, verification result) without validating its shape or range?

## Target
- File/function: [pkg/cmd/run/view/logs.go:280](pkg/cmd/run/view/logs.go#L280) - `stepLogFilenameRegexp`
- Entrypoint: gh run view
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Return a crafted JSON body from an attacker-controlled host or an attacker-owned object.
- Invariant to test: Every response field used for a trust decision is validated against an allowlist before use.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test of hostile JSON payloads asserting rejection.
