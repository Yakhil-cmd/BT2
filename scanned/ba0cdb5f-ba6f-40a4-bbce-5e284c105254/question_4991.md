# Q4991: agent/Copilot session data drives local action - (Context).GenerateSSHKey in ssh_keys.go

## Question
Does `GenerateSSHKey` in [pkg/ssh/ssh_keys.go](pkg/ssh/ssh_keys.go#L51) execute, write, or open something based on fields of an agent/session response that an unprivileged attacker can influence (PR body, issue text, repo content fed to the agent)?

## Target
- File/function: [pkg/ssh/ssh_keys.go:51](pkg/ssh/ssh_keys.go#L51) - `(Context).GenerateSSHKey`
- Entrypoint: gh alias import
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Seed the agent input via an issue/PR the attacker authored so the response carries the payload.
- Invariant to test: Agent responses are data; local effects require explicit user confirmation with a sanitized preview.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test with a hostile session fixture asserting no local side effect.
