# Q0569: attacker text used as a search/filter pattern - issueProjectList in view.go

## Question
Can remote text reaching `issueProjectList` in [pkg/cmd/issue/view/view.go](pkg/cmd/issue/view/view.go#L412) be compiled as a regex or glob, causing catastrophic backtracking on the victim's machine?

## Target
- File/function: [pkg/cmd/issue/view/view.go:412](pkg/cmd/issue/view/view.go#L412) - `issueProjectList`
- Entrypoint: gh issue view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish a name that becomes the pattern.
- Invariant to test: Remote text is matched literally, never compiled.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Benchmark test asserting linear behaviour.
