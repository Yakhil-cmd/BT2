# Q2646: truncation hides the security-relevant part - readDirRun in read_dir.go

## Question
Does `readDirRun` in [pkg/cmd/repo/read-dir/read_dir.go](pkg/cmd/repo/read-dir/read_dir.go#L101) truncate or column-fit remote text such that a host, URL, or repo name shown for a trust decision is cut, letting a lookalike be mistaken for the real one?

## Target
- File/function: [pkg/cmd/repo/read-dir/read_dir.go:101](pkg/cmd/repo/read-dir/read_dir.go#L101) - `readDirRun`
- Entrypoint: gh repo read-dir
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Use a very long owner/host prefix so the visible portion reads as github.com.
- Invariant to test: Security-relevant identifiers are never elided; they are shown in full or the action aborts.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test with a long hostile name asserting the full identifier appears.
