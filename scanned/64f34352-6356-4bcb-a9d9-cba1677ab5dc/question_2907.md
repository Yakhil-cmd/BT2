# Q2907: index/label mismatch after filtering - logoutRun in logout.go

## Question
Can the option list built in `logoutRun` in [pkg/cmd/auth/logout/logout.go](pkg/cmd/auth/logout/logout.go#L79) be filtered or deduplicated so the chosen index maps to a different underlying object than the label shown?

## Target
- File/function: [pkg/cmd/auth/logout/logout.go:79](pkg/cmd/auth/logout/logout.go#L79) - `logoutRun`
- Entrypoint: gh auth logout
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish entries whose labels collide after truncation/dedup.
- Invariant to test: Selection returns the object identity, not a recomputed index.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with colliding labels asserting the selected object matches the label.
