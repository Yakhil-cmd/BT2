# Q4227: cached response written world-readable - newCodeCmd in code.go

## Question
Does the on-disk cache used by `newCodeCmd` in [pkg/cmd/codespace/code.go](pkg/cmd/codespace/code.go#L11) store authenticated response bodies (including private data) with permissive modes or predictable names in a shared directory?

## Target
- File/function: [pkg/cmd/codespace/code.go:11](pkg/cmd/codespace/code.go#L11) - `newCodeCmd`
- Entrypoint: gh codespace code
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Read another user's gh cache on a shared build host.
- Invariant to test: Cache files live in the user's private dir with 0600.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting cache file mode and location.
