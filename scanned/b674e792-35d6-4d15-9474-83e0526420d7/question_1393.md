# Q1393: telemetry payload includes untrusted or sensitive data - NewCmdCopilot in copilot.go

## Question
Does `NewCmdCopilot` in [pkg/cmd/copilot/copilot.go](pkg/cmd/copilot/copilot.go#L42) include command arguments, repo coordinates, or error text (which may embed tokens or attacker-controlled content) in an outbound telemetry payload?

## Target
- File/function: [pkg/cmd/copilot/copilot.go:42](pkg/cmd/copilot/copilot.go#L42) - `NewCmdCopilot`
- Entrypoint: gh copilot copilot
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Force an error whose message embeds sensitive context.
- Invariant to test: Telemetry carries only allowlisted, non-sensitive fields.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the serialized payload fields.
