# Q5768: host-scoped client leaked into another flow - SmartBaseRepoFunc in default.go

## Question
Can the client/transport constructed in `SmartBaseRepoFunc` in [pkg/cmd/factory/default.go](pkg/cmd/factory/default.go#L152) (with its auth round-tripper) be reused by a later flow whose target host came from a repo/remote/host string or API response field the attacker publishes?

## Target
- File/function: [pkg/cmd/factory/default.go:152](pkg/cmd/factory/default.go#L152) - `SmartBaseRepoFunc`
- Entrypoint: gh factory default
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Chain two operations where the second targets an attacker host.
- Invariant to test: Auth round-trippers verify the request host on every call.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test reusing the client against a foreign host asserting the header is dropped.
