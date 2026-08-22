# Q5581: attacker text used as a search/filter pattern - parseSection in browse.go

## Question
Can remote text reaching `parseSection` in [pkg/cmd/browse/browse.go](pkg/cmd/browse/browse.go#L230) be compiled as a regex or glob, causing catastrophic backtracking on the victim's machine?

## Target
- File/function: [pkg/cmd/browse/browse.go:230](pkg/cmd/browse/browse.go#L230) - `parseSection`
- Entrypoint: gh browse browse
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish a name that becomes the pattern.
- Invariant to test: Remote text is matched literally, never compiled.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Benchmark test asserting linear behaviour.
