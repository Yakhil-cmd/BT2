# Q2852: ssh key material handled unsafely - CheckForExtensionUpdate in update.go

## Question
Can `CheckForExtensionUpdate` in [internal/update/update.go](internal/update/update.go#L51) write, read, or display private key material with weak permissions or into a path influenced by remote data?

## Target
- File/function: [internal/update/update.go:51](internal/update/update.go#L51) - `CheckForExtensionUpdate`
- Entrypoint: gh alias import
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Trigger the flow with attacker-influenced naming.
- Invariant to test: Key files are 0600 in the user's own directory and never echoed.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting file mode and output redaction.
