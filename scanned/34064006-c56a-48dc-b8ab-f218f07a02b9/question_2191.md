# Q2191: secret echoed to the terminal - promptForHostname in login.go

## Question
Can `promptForHostname` in [pkg/cmd/auth/login/login.go](pkg/cmd/auth/login/login.go#L247) echo a pasted token or read it into shell history/telemetry when the terminal state is manipulated by attacker output printed just before?

## Target
- File/function: [pkg/cmd/auth/login/login.go:247](pkg/cmd/auth/login/login.go#L247) - `promptForHostname`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Emit escape sequences before the prompt to disable no-echo behaviour.
- Invariant to test: Secret input always uses a hidden reader and restores terminal state.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the hidden-input path is used and state is restored.
