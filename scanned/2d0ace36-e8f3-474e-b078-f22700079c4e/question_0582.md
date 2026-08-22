# Q0582: attacker text used as a search/filter pattern - printTable in output.go

## Question
Can remote text reaching `printTable` in [pkg/cmd/pr/checks/output.go](pkg/cmd/pr/checks/output.go#L94) be compiled as a regex or glob, causing catastrophic backtracking on the victim's machine?

## Target
- File/function: [pkg/cmd/pr/checks/output.go:94](pkg/cmd/pr/checks/output.go#L94) - `printTable`
- Entrypoint: gh pr checks
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish a name that becomes the pattern.
- Invariant to test: Remote text is matched literally, never compiled.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Benchmark test asserting linear behaviour.
