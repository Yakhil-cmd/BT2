# Q5822: hostile JSON drives a security decision - forkRun in fork.go

## Question
Does `forkRun` in [pkg/cmd/repo/fork/fork.go](pkg/cmd/repo/fork/fork.go#L159) unmarshal a response field that later gates a security decision (host, path, permission, verification result) without validating its shape or range?

## Target
- File/function: [pkg/cmd/repo/fork/fork.go:159](pkg/cmd/repo/fork/fork.go#L159) - `forkRun`
- Entrypoint: gh repo fork
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Return a crafted JSON body from an attacker-controlled host or an attacker-owned object.
- Invariant to test: Every response field used for a trust decision is validated against an allowlist before use.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test of hostile JSON payloads asserting rejection.
