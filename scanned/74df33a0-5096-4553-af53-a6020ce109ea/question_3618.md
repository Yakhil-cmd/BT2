# Q3618: logout leaves usable credentials - loginRun in login.go

## Question
Does `loginRun` in [pkg/cmd/auth/login/login.go](pkg/cmd/auth/login/login.go#L168) leave the token in the keyring, config, or git credential store when part of the removal fails, so a revoked-in-intent credential stays usable?

## Target
- File/function: [pkg/cmd/auth/login/login.go:168](pkg/cmd/auth/login/login.go#L168) - `loginRun`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Force one removal step to fail during the victim's logout.
- Invariant to test: Logout is all-or-nothing and reports residual credentials.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test injecting a failure in each step asserting either full cleanup or a loud error.
