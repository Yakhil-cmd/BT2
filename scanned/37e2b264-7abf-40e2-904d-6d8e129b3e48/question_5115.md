# Q5115: index/label mismatch after filtering - newPrompter in default.go

## Question
Can the option list built in `newPrompter` in [pkg/cmd/factory/default.go](pkg/cmd/factory/default.go#L256) be filtered or deduplicated so the chosen index maps to a different underlying object than the label shown?

## Target
- File/function: [pkg/cmd/factory/default.go:256](pkg/cmd/factory/default.go#L256) - `newPrompter`
- Entrypoint: gh factory default
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish entries whose labels collide after truncation/dedup.
- Invariant to test: Selection returns the object identity, not a recomputed index.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with colliding labels asserting the selected object matches the label.
