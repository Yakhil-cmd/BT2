# Q0081: token attached to non-matching host - NewHTTPClient in http_client.go

## Question
Can `NewHTTPClient` in [api/http_client.go](api/http_client.go#L33) attach the token stored for one host to a request whose host was derived from a repo/remote/host string or API response field the attacker publishes?

## Target
- File/function: [api/http_client.go:33](api/http_client.go#L33) - `NewHTTPClient`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish a repo/remote that resolves to a host the attacker controls while the victim's active token is for github.com.
- Invariant to test: A token is only ever sent to the exact host it was issued for.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Unit test with two configured hosts asserting the header matches the request host.
