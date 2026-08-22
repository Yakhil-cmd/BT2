# Q4281: telemetry payload includes untrusted or sensitive data - CheckForUpdate in update.go

## Question
Does `CheckForUpdate` in [internal/update/update.go](internal/update/update.go#L92) include command arguments, repo coordinates, or error text (which may embed tokens or attacker-controlled content) in an outbound telemetry payload?

## Target
- File/function: [internal/update/update.go:92](internal/update/update.go#L92) - `CheckForUpdate`
- Entrypoint: gh alias import
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Force an error whose message embeds sensitive context.
- Invariant to test: Telemetry carries only allowlisted, non-sensitive fields.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the serialized payload fields.
