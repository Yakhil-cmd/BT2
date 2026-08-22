# Q0705: telemetry payload includes untrusted or sensitive data - GetSecretEntity in shared.go

## Question
Does `GetSecretEntity` in [pkg/cmd/secret/shared/shared.go](pkg/cmd/secret/shared/shared.go#L46) include command arguments, repo coordinates, or error text (which may embed tokens or attacker-controlled content) in an outbound telemetry payload?

## Target
- File/function: [pkg/cmd/secret/shared/shared.go:46](pkg/cmd/secret/shared/shared.go#L46) - `GetSecretEntity`
- Entrypoint: gh secret
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Force an error whose message embeds sensitive context.
- Invariant to test: Telemetry carries only allowlisted, non-sensitive fields.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the serialized payload fields.
