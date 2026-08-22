# Q5131: host header/base path mixing for enterprise - startPage in pagination.go

## Question
Can `startPage` in [pkg/cmd/api/pagination.go](pkg/cmd/api/pagination.go#L210) combine a dotcom base path with an enterprise host (or the reverse) so a request intended for one API surface is sent, authenticated, to another?

## Target
- File/function: [pkg/cmd/api/pagination.go:210](pkg/cmd/api/pagination.go#L210) - `startPage`
- Entrypoint: gh api pagination
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Configure/point gh at an attacker host that looks enterprise-shaped.
- Invariant to test: Base path selection and host selection derive from one classification.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting URL construction per host class.
