# Q5746: credential helper install widens scope - Login in login_flow.go

## Question
Can `Login` in [pkg/cmd/auth/shared/login_flow.go](pkg/cmd/auth/shared/login_flow.go#L50) install or rewrite a git credential helper entry whose URL pattern is broader than the authenticated host (wildcard, scheme-less, or path-less), so unrelated hosts receive the token?

## Target
- File/function: [pkg/cmd/auth/shared/login_flow.go:50](pkg/cmd/auth/shared/login_flow.go#L50) - `Login`
- Entrypoint: gh auth
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish repos on lookalike hosts that then match the installed helper pattern.
- Invariant to test: Helper entries are written with an exact `https://host` key.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the written gitconfig section key is exactly the authenticated host.
