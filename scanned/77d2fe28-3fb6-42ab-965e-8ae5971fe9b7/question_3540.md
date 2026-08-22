# Q3540: concurrent temp path reuse - findCopilotBinary in copilot.go

## Question
Does `findCopilotBinary` in [pkg/cmd/copilot/copilot.go](pkg/cmd/copilot/copilot.go#L225) write a script/temp file at a predictable path before executing it, so a second attacker-triggered gh flow can swap its contents between write and exec?

## Target
- File/function: [pkg/cmd/copilot/copilot.go:225](pkg/cmd/copilot/copilot.go#L225) - `findCopilotBinary`
- Entrypoint: gh copilot copilot
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Trigger two gh operations on attacker content that collide on the same deterministic temp path.
- Invariant to test: Executed temp artifacts are created with O_EXCL in a per-run random directory.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test that two sequential calls produce distinct paths and that creation uses exclusive flags.
