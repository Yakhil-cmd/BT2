# Q2112: failure path continues execution - findCopilotBinary in copilot.go

## Question
If the subprocess launched by `findCopilotBinary` in [pkg/cmd/copilot/copilot.go](pkg/cmd/copilot/copilot.go#L225) fails or returns attacker-shaped stderr, does the caller continue on a fallback path that skips a security check?

## Target
- File/function: [pkg/cmd/copilot/copilot.go:225](pkg/cmd/copilot/copilot.go#L225) - `findCopilotBinary`
- Entrypoint: gh copilot copilot
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Make the child fail deterministically (e.g. force git to error) so gh falls back to a less-validated code path.
- Invariant to test: A failed subprocess must abort the operation, never downgrade to an unchecked fallback.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Stub the runner to return an error and assert the caller aborts rather than proceeding.
