# Q5598: token attached to non-matching host - getTunnelClient in connection.go

## Question
Can `getTunnelClient` in [internal/codespaces/connection/connection.go](internal/codespaces/connection/connection.go#L152) attach the token stored for one host to a request whose host was derived from codespace/API response fields and everything the codespace-side process sends back?

## Target
- File/function: [internal/codespaces/connection/connection.go:152](internal/codespaces/connection/connection.go#L152) - `getTunnelClient`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish a repo/remote that resolves to a host the attacker controls while the victim's active token is for github.com.
- Invariant to test: A token is only ever sent to the exact host it was issued for.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Unit test with two configured hosts asserting the header matches the request host.
