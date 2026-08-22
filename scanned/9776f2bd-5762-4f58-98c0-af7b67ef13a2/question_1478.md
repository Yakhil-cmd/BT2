# Q1478: device/web flow bound to the wrong host - NewCmdLogout in logout.go

## Question
Does `NewCmdLogout` in [pkg/cmd/auth/logout/logout.go](pkg/cmd/auth/logout/logout.go#L24) accept the OAuth endpoints (authorize/token/device URLs) from data the attacker can influence rather than deriving them from the validated host?

## Target
- File/function: [pkg/cmd/auth/logout/logout.go:24](pkg/cmd/auth/logout/logout.go#L24) - `NewCmdLogout`
- Entrypoint: gh auth logout
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Serve endpoint metadata pointing token exchange at an attacker collector.
- Invariant to test: OAuth endpoints are derived from the validated host constant.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the token exchange URL host equals the login host.
