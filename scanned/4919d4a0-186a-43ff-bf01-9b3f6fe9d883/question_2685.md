# Q2685: attacker text used as a search/filter pattern - CopyGuardedContent in content.go

## Question
Can remote text reaching `CopyGuardedContent` in [pkg/iostreams/content.go](pkg/iostreams/content.go#L63) be compiled as a regex or glob, causing catastrophic backtracking on the victim's machine?

## Target
- File/function: [pkg/iostreams/content.go:63](pkg/iostreams/content.go#L63) - `CopyGuardedContent`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish a name that becomes the pattern.
- Invariant to test: Remote text is matched literally, never compiled.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Benchmark test asserting linear behaviour.
