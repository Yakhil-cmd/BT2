# Q5680: attacker-chosen executable path - findCopilotBinary in copilot.go

## Question
Can `findCopilotBinary` in [pkg/cmd/copilot/copilot.go](pkg/cmd/copilot/copilot.go#L225) be steered into executing a binary or script path that came from remote data (an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes) rather than from a fixed, validated location?

## Target
- File/function: [pkg/cmd/copilot/copilot.go:225](pkg/cmd/copilot/copilot.go#L225) - `findCopilotBinary`
- Entrypoint: gh copilot copilot
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Serve a manifest/response whose name or path field resolves to a file the attacker also caused to be written on disk.
- Invariant to test: The executable path must come from a constant or a validated install root, never from a server response.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Unit test with a fake runner asserting the executed path is rooted under the expected directory.
