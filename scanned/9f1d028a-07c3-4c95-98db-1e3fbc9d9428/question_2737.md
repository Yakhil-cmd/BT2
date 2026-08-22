# Q2737: cached response written world-readable - GetCodespaceConnection in codespaces.go

## Question
Does the on-disk cache used by `GetCodespaceConnection` in [internal/codespaces/codespaces.go](internal/codespaces/codespaces.go#L60) store authenticated response bodies (including private data) with permissive modes or predictable names in a shared directory?

## Target
- File/function: [internal/codespaces/codespaces.go:60](internal/codespaces/codespaces.go#L60) - `GetCodespaceConnection`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Read another user's gh cache on a shared build host.
- Invariant to test: Cache files live in the user's private dir with 0600.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting cache file mode and location.
