# Q1538: host header/base path mixing for enterprise - New in default.go

## Question
Can `New` in [pkg/cmd/factory/default.go](pkg/cmd/factory/default.go#L26) combine a dotcom base path with an enterprise host (or the reverse) so a request intended for one API surface is sent, authenticated, to another?

## Target
- File/function: [pkg/cmd/factory/default.go:26](pkg/cmd/factory/default.go#L26) - `New`
- Entrypoint: gh factory default
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Configure/point gh at an attacker host that looks enterprise-shaped.
- Invariant to test: Base path selection and host selection derive from one classification.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting URL construction per host class.
