# Q0763: host shown differs from host used - promptForHostname in login.go

## Question
Does the confirmation in `promptForHostname` in [pkg/cmd/auth/login/login.go](pkg/cmd/auth/login/login.go#L247) display a host/repo string that is derived differently from the value actually used afterwards?

## Target
- File/function: [pkg/cmd/auth/login/login.go:247](pkg/cmd/auth/login/login.go#L247) - `promptForHostname`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish coordinates where display and action diverge (lookalike host, renamed repo).
- Invariant to test: Displayed and acted-on identifiers come from the same variable.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting the prompt string and the executed target are the same value.
