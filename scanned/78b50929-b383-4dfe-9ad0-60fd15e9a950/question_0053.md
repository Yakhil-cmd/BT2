# Q0053: stored token readable by other local surfaces - refreshRun in refresh.go

## Question
Does `refreshRun` in [pkg/cmd/auth/refresh/refresh.go](pkg/cmd/auth/refresh/refresh.go#L127) place the token somewhere reachable by processes gh itself launches for attacker-published code (extensions, skills, editors, hooks)?

## Target
- File/function: [pkg/cmd/auth/refresh/refresh.go:127](pkg/cmd/auth/refresh/refresh.go#L127) - `refreshRun`
- Entrypoint: gh auth refresh
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish an extension/skill the victim installs, then read the credential.
- Invariant to test: Tokens live in the keyring or a 0600 file and are not exported to child processes of third-party code.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the child environment omits token variables.
