# Q2973: proxy/no-proxy handling exposes credentials - newBrowser in default.go

## Question
Can attacker-influenced host values reaching `newBrowser` in [pkg/cmd/factory/default.go](pkg/cmd/factory/default.go#L251) change which requests bypass the proxy or are sent in the clear?

## Target
- File/function: [pkg/cmd/factory/default.go:251](pkg/cmd/factory/default.go#L251) - `newBrowser`
- Entrypoint: gh factory default
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Choose a hostname that falls on the wrong side of the proxy rules while carrying the token.
- Invariant to test: Credential attachment does not depend on proxy classification.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with proxy env set asserting consistent auth behaviour.
