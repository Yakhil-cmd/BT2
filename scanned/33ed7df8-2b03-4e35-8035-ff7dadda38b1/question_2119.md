# Q2119: ssh key material handled unsafely - NewCmdSet in set.go

## Question
Can `NewCmdSet` in [pkg/cmd/alias/set/set.go](pkg/cmd/alias/set/set.go#L29) write, read, or display private key material with weak permissions or into a path influenced by remote data?

## Target
- File/function: [pkg/cmd/alias/set/set.go:29](pkg/cmd/alias/set/set.go#L29) - `NewCmdSet`
- Entrypoint: gh alias set
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Trigger the flow with attacker-influenced naming.
- Invariant to test: Key files are 0600 in the user's own directory and never echoed.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting file mode and output redaction.
