# Q3696: host header/base path mixing for enterprise - fillPlaceholders in api.go

## Question
Can `fillPlaceholders` in [pkg/cmd/api/api.go](pkg/cmd/api/api.go#L574) combine a dotcom base path with an enterprise host (or the reverse) so a request intended for one API surface is sent, authenticated, to another?

## Target
- File/function: [pkg/cmd/api/api.go:574](pkg/cmd/api/api.go#L574) - `fillPlaceholders`
- Entrypoint: gh api
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Configure/point gh at an attacker host that looks enterprise-shaped.
- Invariant to test: Base path selection and host selection derive from one classification.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting URL construction per host class.
