# Q3534: truncation hides the security-relevant part - followLogs in create.go

## Question
Does `followLogs` in [pkg/cmd/agent-task/create/create.go](pkg/cmd/agent-task/create/create.go#L263) truncate or column-fit remote text such that a host, URL, or repo name shown for a trust decision is cut, letting a lookalike be mistaken for the real one?

## Target
- File/function: [pkg/cmd/agent-task/create/create.go:263](pkg/cmd/agent-task/create/create.go#L263) - `followLogs`
- Entrypoint: gh agent task create
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Use a very long owner/host prefix so the visible portion reads as github.com.
- Invariant to test: Security-relevant identifiers are never elided; they are shown in full or the action aborts.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test with a long hostile name asserting the full identifier appears.
