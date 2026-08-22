# Q4955: cached response written world-readable - resolveCapiURL in capi.go

## Question
Does the on-disk cache used by `resolveCapiURL` in [pkg/cmd/agent-task/shared/capi.go](pkg/cmd/agent-task/shared/capi.go#L48) store authenticated response bodies (including private data) with permissive modes or predictable names in a shared directory?

## Target
- File/function: [pkg/cmd/agent-task/shared/capi.go:48](pkg/cmd/agent-task/shared/capi.go#L48) - `resolveCapiURL`
- Entrypoint: gh agent task
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Read another user's gh cache on a shared build host.
- Invariant to test: Cache files live in the user's private dir with 0600.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting cache file mode and location.
