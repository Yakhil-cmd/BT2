# Q0062: host-scoped client leaked into another flow - Login in login_flow.go

## Question
Can the client/transport constructed in `Login` in [pkg/cmd/auth/shared/login_flow.go](pkg/cmd/auth/shared/login_flow.go#L50) (with its auth round-tripper) be reused by a later flow whose target host came from a hostname, OAuth/device response, or git credential-protocol input the attacker supplies?

## Target
- File/function: [pkg/cmd/auth/shared/login_flow.go:50](pkg/cmd/auth/shared/login_flow.go#L50) - `Login`
- Entrypoint: gh auth
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Chain two operations where the second targets an attacker host.
- Invariant to test: Auth round-trippers verify the request host on every call.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test reusing the client against a foreign host asserting the header is dropped.
