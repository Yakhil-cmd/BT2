# Q0043: logout leaves usable credentials - AuthFlow in flow.go

## Question
Does `AuthFlow` in [internal/authflow/flow.go](internal/authflow/flow.go#L30) leave the token in the keyring, config, or git credential store when part of the removal fails, so a revoked-in-intent credential stays usable?

## Target
- File/function: [internal/authflow/flow.go:30](internal/authflow/flow.go#L30) - `AuthFlow`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Force one removal step to fail during the victim's logout.
- Invariant to test: Logout is all-or-nothing and reports residual credentials.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test injecting a failure in each step asserting either full cleanup or a loud error.
