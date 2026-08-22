# Q5059: env-provided token used against a foreign host - Login in login_flow.go

## Question
Does `Login` in [pkg/cmd/auth/shared/login_flow.go](pkg/cmd/auth/shared/login_flow.go#L50) apply a GH_TOKEN/GITHUB_TOKEN environment credential to requests whose host was derived from attacker-published repository metadata?

## Target
- File/function: [pkg/cmd/auth/shared/login_flow.go:50](pkg/cmd/auth/shared/login_flow.go#L50) - `Login`
- Entrypoint: gh auth
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish a repo whose remote points at an attacker host and let a CI job running gh with GH_TOKEN operate in it.
- Invariant to test: Environment tokens are bound to the configured default host only.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with GH_TOKEN set and a foreign-host request asserting no Authorization header.
