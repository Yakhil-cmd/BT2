# Q3210: secret echoed to the terminal - updateRun in update.go

## Question
Can `updateRun` in [pkg/cmd/skills/update/update.go](pkg/cmd/skills/update/update.go#L143) echo a pasted token or read it into shell history/telemetry when the terminal state is manipulated by attacker output printed just before?

## Target
- File/function: [pkg/cmd/skills/update/update.go:143](pkg/cmd/skills/update/update.go#L143) - `updateRun`
- Entrypoint: gh skills update
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Emit escape sequences before the prompt to disable no-echo behaviour.
- Invariant to test: Secret input always uses a hidden reader and restores terminal state.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the hidden-input path is used and state is restored.
