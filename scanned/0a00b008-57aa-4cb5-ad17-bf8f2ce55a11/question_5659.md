# Q5659: index/label mismatch after filtering - chooseCodespaceFromList in common.go

## Question
Can the option list built in `chooseCodespaceFromList` in [pkg/cmd/codespace/common.go](pkg/cmd/codespace/common.go#L93) be filtered or deduplicated so the chosen index maps to a different underlying object than the label shown?

## Target
- File/function: [pkg/cmd/codespace/common.go:93](pkg/cmd/codespace/common.go#L93) - `chooseCodespaceFromList`
- Entrypoint: gh codespace common
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish entries whose labels collide after truncation/dedup.
- Invariant to test: Selection returns the object identity, not a recomputed index.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with colliding labels asserting the selected object matches the label.
