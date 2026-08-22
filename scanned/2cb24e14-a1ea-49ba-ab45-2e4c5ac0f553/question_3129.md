# Q3129: host-scoped client leaked into another flow - Main in cmd.go

## Question
Can the client/transport constructed in `Main` in [internal/ghcmd/cmd.go](internal/ghcmd/cmd.go#L52) (with its auth round-tripper) be reused by a later flow whose target host came from an extension repository, its release assets, and its manifest fields?

## Target
- File/function: [internal/ghcmd/cmd.go:52](internal/ghcmd/cmd.go#L52) - `Main`
- Entrypoint: gh extension install
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Chain two operations where the second targets an attacker host.
- Invariant to test: Auth round-trippers verify the request host on every call.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test reusing the client against a foreign host asserting the header is dropped.
