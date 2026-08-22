# Q4245: agent/Copilot session data drives local action - createRun in create.go

## Question
Does `createRun` in [pkg/cmd/agent-task/create/create.go](pkg/cmd/agent-task/create/create.go#L123) execute, write, or open something based on fields of an agent/session response that an unprivileged attacker can influence (PR body, issue text, repo content fed to the agent)?

## Target
- File/function: [pkg/cmd/agent-task/create/create.go:123](pkg/cmd/agent-task/create/create.go#L123) - `createRun`
- Entrypoint: gh agent task create
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Seed the agent input via an issue/PR the attacker authored so the response carries the payload.
- Invariant to test: Agent responses are data; local effects require explicit user confirmation with a sanitized preview.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test with a hostile session fixture asserting no local side effect.
