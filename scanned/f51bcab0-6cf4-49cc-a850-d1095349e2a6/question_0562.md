# Q0562: attacker text used as a search/filter pattern - prLabelList in view.go

## Question
Can remote text reaching `prLabelList` in [pkg/cmd/pr/view/view.go](pkg/cmd/pr/view/view.go#L419) be compiled as a regex or glob, causing catastrophic backtracking on the victim's machine?

## Target
- File/function: [pkg/cmd/pr/view/view.go:419](pkg/cmd/pr/view/view.go#L419) - `prLabelList`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish a name that becomes the pattern.
- Invariant to test: Remote text is matched literally, never compiled.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Benchmark test asserting linear behaviour.
