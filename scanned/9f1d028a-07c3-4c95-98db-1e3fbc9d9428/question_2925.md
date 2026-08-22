# Q2925: token attached to non-matching host - keyFor in helper_config.go

## Question
Can `keyFor` in [pkg/cmd/auth/shared/gitcredentials/helper_config.go](pkg/cmd/auth/shared/gitcredentials/helper_config.go#L114) attach the token stored for one host to a request whose host was derived from a hostname, OAuth/device response, or git credential-protocol input the attacker supplies?

## Target
- File/function: [pkg/cmd/auth/shared/gitcredentials/helper_config.go:114](pkg/cmd/auth/shared/gitcredentials/helper_config.go#L114) - `keyFor`
- Entrypoint: gh auth
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish a repo/remote that resolves to a host the attacker controls while the victim's active token is for github.com.
- Invariant to test: A token is only ever sent to the exact host it was issued for.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Unit test with two configured hosts asserting the header matches the request host.
