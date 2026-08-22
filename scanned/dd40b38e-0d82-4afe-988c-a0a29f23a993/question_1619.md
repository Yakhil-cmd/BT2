# Q1619: secret echoed to the terminal - (promptingPRResolver).Resolve in checkout.go

## Question
Can `Resolve` in [pkg/cmd/pr/checkout/checkout.go](pkg/cmd/pr/checkout/checkout.go#L436) echo a pasted token or read it into shell history/telemetry when the terminal state is manipulated by attacker output printed just before?

## Target
- File/function: [pkg/cmd/pr/checkout/checkout.go:436](pkg/cmd/pr/checkout/checkout.go#L436) - `(promptingPRResolver).Resolve`
- Entrypoint: gh pr checkout
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Emit escape sequences before the prompt to disable no-echo behaviour.
- Invariant to test: Secret input always uses a hidden reader and restores terminal state.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the hidden-input path is used and state is restored.
