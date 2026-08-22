# Q1053: index/label mismatch after filtering - resolveHosts in install.go

## Question
Can the option list built in `resolveHosts` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L913) be filtered or deduplicated so the chosen index maps to a different underlying object than the label shown?

## Target
- File/function: [pkg/cmd/skills/install/install.go:913](pkg/cmd/skills/install/install.go#L913) - `resolveHosts`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish entries whose labels collide after truncation/dedup.
- Invariant to test: Selection returns the object identity, not a recomputed index.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with colliding labels asserting the selected object matches the label.
