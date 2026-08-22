# Q1278: cached response written world-readable - NewCmdView in view.go

## Question
Does the on-disk cache used by `NewCmdView` in [pkg/cmd/issue/view/view.go](pkg/cmd/issue/view/view.go#L42) store authenticated response bodies (including private data) with permissive modes or predictable names in a shared directory?

## Target
- File/function: [pkg/cmd/issue/view/view.go:42](pkg/cmd/issue/view/view.go#L42) - `NewCmdView`
- Entrypoint: gh issue view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Read another user's gh cache on a shared build host.
- Invariant to test: Cache files live in the user's private dir with 0600.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting cache file mode and location.
