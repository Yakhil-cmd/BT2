# Q5671: ssh key material handled unsafely - createRun in create.go

## Question
Can `createRun` in [pkg/cmd/agent-task/create/create.go](pkg/cmd/agent-task/create/create.go#L123) write, read, or display private key material with weak permissions or into a path influenced by remote data?

## Target
- File/function: [pkg/cmd/agent-task/create/create.go:123](pkg/cmd/agent-task/create/create.go#L123) - `createRun`
- Entrypoint: gh agent task create
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Trigger the flow with attacker-influenced naming.
- Invariant to test: Key files are 0600 in the user's own directory and never echoed.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting file mode and output redaction.
