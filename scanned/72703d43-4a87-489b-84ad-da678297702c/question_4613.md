# Q4613: secret echoed to the terminal - resolveRepoArg in install.go

## Question
Can `resolveRepoArg` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L580) echo a pasted token or read it into shell history/telemetry when the terminal state is manipulated by attacker output printed just before?

## Target
- File/function: [pkg/cmd/skills/install/install.go:580](pkg/cmd/skills/install/install.go#L580) - `resolveRepoArg`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Emit escape sequences before the prompt to disable no-echo behaviour.
- Invariant to test: Secret input always uses a hidden reader and restores terminal state.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the hidden-input path is used and state is restored.
