# Q0696: ssh key material handled unsafely - ValidAliasExpansionFunc in validations.go

## Question
Can `ValidAliasExpansionFunc` in [pkg/cmd/alias/shared/validations.go](pkg/cmd/alias/shared/validations.go#L36) write, read, or display private key material with weak permissions or into a path influenced by remote data?

## Target
- File/function: [pkg/cmd/alias/shared/validations.go:36](pkg/cmd/alias/shared/validations.go#L36) - `ValidAliasExpansionFunc`
- Entrypoint: gh alias
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Trigger the flow with attacker-influenced naming.
- Invariant to test: Key files are 0600 in the user's own directory and never echoed.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting file mode and output redaction.
