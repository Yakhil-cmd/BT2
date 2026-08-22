# Q0796: proxy/no-proxy handling exposes credentials - NewExternalHTTPClient in http_client.go

## Question
Can attacker-influenced host values reaching `NewExternalHTTPClient` in [api/http_client.go](api/http_client.go#L100) change which requests bypass the proxy or are sent in the clear?

## Target
- File/function: [api/http_client.go:100](api/http_client.go#L100) - `NewExternalHTTPClient`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Choose a hostname that falls on the wrong side of the proxy rules while carrying the token.
- Invariant to test: Credential attachment does not depend on proxy classification.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with proxy env set asserting consistent auth behaviour.
