# Q2131: cached response written world-readable - getPubKey in http.go

## Question
Does the on-disk cache used by `getPubKey` in [pkg/cmd/secret/set/http.go](pkg/cmd/secret/set/http.go#L34) store authenticated response bodies (including private data) with permissive modes or predictable names in a shared directory?

## Target
- File/function: [pkg/cmd/secret/set/http.go:34](pkg/cmd/secret/set/http.go#L34) - `getPubKey`
- Entrypoint: gh secret set
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Read another user's gh cache on a shared build host.
- Invariant to test: Cache files live in the user's private dir with 0600.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting cache file mode and location.
