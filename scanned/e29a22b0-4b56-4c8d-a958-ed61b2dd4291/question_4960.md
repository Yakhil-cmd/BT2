# Q4960: ssh key material handled unsafely - fetchJobWithBackoff in create.go

## Question
Can `fetchJobWithBackoff` in [pkg/cmd/agent-task/create/create.go](pkg/cmd/agent-task/create/create.go#L235) write, read, or display private key material with weak permissions or into a path influenced by remote data?

## Target
- File/function: [pkg/cmd/agent-task/create/create.go:235](pkg/cmd/agent-task/create/create.go#L235) - `fetchJobWithBackoff`
- Entrypoint: gh agent task create
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Trigger the flow with attacker-influenced naming.
- Invariant to test: Key files are 0600 in the user's own directory and never echoed.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting file mode and output redaction.
