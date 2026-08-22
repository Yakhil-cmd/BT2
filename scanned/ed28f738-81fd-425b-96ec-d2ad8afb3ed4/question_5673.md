# Q5673: telemetry payload includes untrusted or sensitive data - fetchJobWithBackoff in create.go

## Question
Does `fetchJobWithBackoff` in [pkg/cmd/agent-task/create/create.go](pkg/cmd/agent-task/create/create.go#L235) include command arguments, repo coordinates, or error text (which may embed tokens or attacker-controlled content) in an outbound telemetry payload?

## Target
- File/function: [pkg/cmd/agent-task/create/create.go:235](pkg/cmd/agent-task/create/create.go#L235) - `fetchJobWithBackoff`
- Entrypoint: gh agent task create
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Force an error whose message embeds sensitive context.
- Invariant to test: Telemetry carries only allowlisted, non-sensitive fields.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the serialized payload fields.
