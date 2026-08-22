# Q4083: secret echoed to the terminal - editRun in edit.go

## Question
Can `editRun` in [pkg/cmd/gist/edit/edit.go](pkg/cmd/gist/edit/edit.go#L118) echo a pasted token or read it into shell history/telemetry when the terminal state is manipulated by attacker output printed just before?

## Target
- File/function: [pkg/cmd/gist/edit/edit.go:118](pkg/cmd/gist/edit/edit.go#L118) - `editRun`
- Entrypoint: gh gist edit
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Emit escape sequences before the prompt to disable no-echo behaviour.
- Invariant to test: Secret input always uses a hidden reader and restores terminal state.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the hidden-input path is used and state is restored.
