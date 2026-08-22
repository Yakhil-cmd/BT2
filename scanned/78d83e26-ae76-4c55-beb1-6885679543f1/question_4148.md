# Q4148: attacker text used as a search/filter pattern - sortComments in comments.go

## Question
Can remote text reaching `sortComments` in [pkg/cmd/pr/shared/comments.go](pkg/cmd/pr/shared/comments.go#L144) be compiled as a regex or glob, causing catastrophic backtracking on the victim's machine?

## Target
- File/function: [pkg/cmd/pr/shared/comments.go:144](pkg/cmd/pr/shared/comments.go#L144) - `sortComments`
- Entrypoint: gh pr
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish a name that becomes the pattern.
- Invariant to test: Remote text is matched literally, never compiled.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Benchmark test asserting linear behaviour.
