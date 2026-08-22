# Q0832: secret echoed to the terminal - newPrompter in default.go

## Question
Can `newPrompter` in [pkg/cmd/factory/default.go](pkg/cmd/factory/default.go#L256) echo a pasted token or read it into shell history/telemetry when the terminal state is manipulated by attacker output printed just before?

## Target
- File/function: [pkg/cmd/factory/default.go:256](pkg/cmd/factory/default.go#L256) - `newPrompter`
- Entrypoint: gh factory default
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Emit escape sequences before the prompt to disable no-echo behaviour.
- Invariant to test: Secret input always uses a hidden reader and restores terminal state.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the hidden-input path is used and state is restored.
