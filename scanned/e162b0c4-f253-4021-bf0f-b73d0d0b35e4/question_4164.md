# Q4164: token attached to non-matching host - connectionReady in codespaces.go

## Question
Can `connectionReady` in [internal/codespaces/codespaces.go](internal/codespaces/codespaces.go#L25) attach the token stored for one host to a request whose host was derived from codespace/API response fields and everything the codespace-side process sends back?

## Target
- File/function: [internal/codespaces/codespaces.go:25](internal/codespaces/codespaces.go#L25) - `connectionReady`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish a repo/remote that resolves to a host the attacker controls while the victim's active token is for github.com.
- Invariant to test: A token is only ever sent to the exact host it was issued for.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Unit test with two configured hosts asserting the header matches the request host.
