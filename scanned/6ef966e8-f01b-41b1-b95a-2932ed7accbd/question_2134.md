# Q2134: ssh key material handled unsafely - GetSecretApp in shared.go

## Question
Can `GetSecretApp` in [pkg/cmd/secret/shared/shared.go](pkg/cmd/secret/shared/shared.go#L66) write, read, or display private key material with weak permissions or into a path influenced by remote data?

## Target
- File/function: [pkg/cmd/secret/shared/shared.go:66](pkg/cmd/secret/shared/shared.go#L66) - `GetSecretApp`
- Entrypoint: gh secret
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Trigger the flow with attacker-influenced naming.
- Invariant to test: Key files are 0600 in the user's own directory and never echoed.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting file mode and output redaction.
