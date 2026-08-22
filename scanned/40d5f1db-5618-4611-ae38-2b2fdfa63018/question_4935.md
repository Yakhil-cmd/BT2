# Q4935: secret echoed to the terminal - (App).UpdatePortVisibility in ports.go

## Question
Can `UpdatePortVisibility` in [pkg/cmd/codespace/ports.go](pkg/cmd/codespace/ports.go#L233) echo a pasted token or read it into shell history/telemetry when the terminal state is manipulated by attacker output printed just before?

## Target
- File/function: [pkg/cmd/codespace/ports.go:233](pkg/cmd/codespace/ports.go#L233) - `(App).UpdatePortVisibility`
- Entrypoint: gh codespace ports
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Emit escape sequences before the prompt to disable no-echo behaviour.
- Invariant to test: Secret input always uses a hidden reader and restores terminal state.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the hidden-input path is used and state is restored.
