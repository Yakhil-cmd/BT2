# Q4978: telemetry payload includes untrusted or sensitive data - ValidAliasNameFunc in validations.go

## Question
Does `ValidAliasNameFunc` in [pkg/cmd/alias/shared/validations.go](pkg/cmd/alias/shared/validations.go#L15) include command arguments, repo coordinates, or error text (which may embed tokens or attacker-controlled content) in an outbound telemetry payload?

## Target
- File/function: [pkg/cmd/alias/shared/validations.go:15](pkg/cmd/alias/shared/validations.go#L15) - `ValidAliasNameFunc`
- Entrypoint: gh alias
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Force an error whose message embeds sensitive context.
- Invariant to test: Telemetry carries only allowlisted, non-sensitive fields.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the serialized payload fields.
