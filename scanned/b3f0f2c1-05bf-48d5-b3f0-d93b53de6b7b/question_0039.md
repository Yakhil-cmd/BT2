# Q0039: token attached to non-matching host - Get in keyring.go

## Question
Can `Get` in [internal/keyring/keyring.go](internal/keyring/keyring.go#L37) attach the token stored for one host to a request whose host was derived from a hostname, OAuth/device response, or git credential-protocol input the attacker supplies?

## Target
- File/function: [internal/keyring/keyring.go:37](internal/keyring/keyring.go#L37) - `Get`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish a repo/remote that resolves to a host the attacker controls while the victim's active token is for github.com.
- Invariant to test: A token is only ever sent to the exact host it was issued for.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Unit test with two configured hosts asserting the header matches the request host.
