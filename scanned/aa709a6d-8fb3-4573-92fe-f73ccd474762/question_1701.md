# Q1701: unauthenticated fallback on error - Main in cmd.go

## Question
When authentication fails inside `Main` in [internal/ghcmd/cmd.go](internal/ghcmd/cmd.go#L52), does it retry unauthenticated (or against a different host) and continue as if it had succeeded?

## Target
- File/function: [internal/ghcmd/cmd.go:52](internal/ghcmd/cmd.go#L52) - `Main`
- Entrypoint: gh extension install
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Force a 401 from the attacker-controlled host and observe the fallback request.
- Invariant to test: Auth failure aborts; no silent downgrade.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting a single failed request and an error.
