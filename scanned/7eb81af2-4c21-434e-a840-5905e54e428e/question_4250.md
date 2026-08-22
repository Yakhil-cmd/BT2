# Q4250: timeout/EOF treated as approval - runCopilot in copilot.go

## Question
Does an EOF or closed stdin in `runCopilot` in [pkg/cmd/copilot/copilot.go](pkg/cmd/copilot/copilot.go#L134) resolve to the affirmative branch?

## Target
- File/function: [pkg/cmd/copilot/copilot.go:134](pkg/cmd/copilot/copilot.go#L134) - `runCopilot`
- Entrypoint: gh copilot copilot
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Run the flow with stdin closed, as in a CI pipeline processing attacker content.
- Invariant to test: EOF is an error, never a yes.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with a closed stdin asserting an error.
