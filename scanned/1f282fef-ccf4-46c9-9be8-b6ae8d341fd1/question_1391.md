# Q1391: secret encrypted for the wrong recipient - fetchJobWithBackoff in create.go

## Question
Can `fetchJobWithBackoff` in [pkg/cmd/agent-task/create/create.go](pkg/cmd/agent-task/create/create.go#L235) fetch the public key from a repository other than the one the user named (base-repo resolution, redirect, override), so the secret is encrypted for an attacker-owned repo?

## Target
- File/function: [pkg/cmd/agent-task/create/create.go:235](pkg/cmd/agent-task/create/create.go#L235) - `fetchJobWithBackoff`
- Entrypoint: gh agent task create
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish a repo/remote that wins base-repo resolution.
- Invariant to test: The key's repository is displayed and matched to the user's explicit target.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with competing coordinates asserting the key source.
