# Q1474: cached response written world-readable - getViewer in flow.go

## Question
Does the on-disk cache used by `getViewer` in [internal/authflow/flow.go](internal/authflow/flow.go#L126) store authenticated response bodies (including private data) with permissive modes or predictable names in a shared directory?

## Target
- File/function: [internal/authflow/flow.go:126](internal/authflow/flow.go#L126) - `getViewer`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Read another user's gh cache on a shared build host.
- Invariant to test: Cache files live in the user's private dir with 0600.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting cache file mode and location.
