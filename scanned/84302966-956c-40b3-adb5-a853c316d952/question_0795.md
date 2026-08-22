# Q0795: cached response written world-readable - NewHTTPClient in http_client.go

## Question
Does the on-disk cache used by `NewHTTPClient` in [api/http_client.go](api/http_client.go#L33) store authenticated response bodies (including private data) with permissive modes or predictable names in a shared directory?

## Target
- File/function: [api/http_client.go:33](api/http_client.go#L33) - `NewHTTPClient`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Read another user's gh cache on a shared build host.
- Invariant to test: Cache files live in the user's private dir with 0600.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting cache file mode and location.
