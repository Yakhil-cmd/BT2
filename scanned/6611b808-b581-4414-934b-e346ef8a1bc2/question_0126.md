# Q0126: proxy/no-proxy handling exposes credentials - fillPlaceholders in api.go

## Question
Can attacker-influenced host values reaching `fillPlaceholders` in [pkg/cmd/api/api.go](pkg/cmd/api/api.go#L574) change which requests bypass the proxy or are sent in the clear?

## Target
- File/function: [pkg/cmd/api/api.go:574](pkg/cmd/api/api.go#L574) - `fillPlaceholders`
- Entrypoint: gh api
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Choose a hostname that falls on the wrong side of the proxy rules while carrying the token.
- Invariant to test: Credential attachment does not depend on proxy classification.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with proxy env set asserting consistent auth behaviour.
