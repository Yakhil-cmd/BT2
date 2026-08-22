# Q2671: attacker text used as a search/filter pattern - (IOStreams).StartPager in iostreams.go

## Question
Can remote text reaching `StartPager` in [pkg/iostreams/iostreams.go](pkg/iostreams/iostreams.go#L216) be compiled as a regex or glob, causing catastrophic backtracking on the victim's machine?

## Target
- File/function: [pkg/iostreams/iostreams.go:216](pkg/iostreams/iostreams.go#L216) - `(IOStreams).StartPager`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish a name that becomes the pattern.
- Invariant to test: Remote text is matched literally, never compiled.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Benchmark test asserting linear behaviour.
