# Q1704: cached response written world-readable - checkForUpdate in cmd.go

## Question
Does the on-disk cache used by `checkForUpdate` in [internal/ghcmd/cmd.go](internal/ghcmd/cmd.go#L318) store authenticated response bodies (including private data) with permissive modes or predictable names in a shared directory?

## Target
- File/function: [internal/ghcmd/cmd.go:318](internal/ghcmd/cmd.go#L318) - `checkForUpdate`
- Entrypoint: gh extension install
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Read another user's gh cache on a shared build host.
- Invariant to test: Cache files live in the user's private dir with 0600.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting cache file mode and location.
