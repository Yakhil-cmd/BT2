# Q4755: unbounded response body - fetchReleasePath in fetch.go

## Question
Does `fetchReleasePath` in [pkg/cmd/release/shared/fetch.go](pkg/cmd/release/shared/fetch.go#L281) read the whole response body into memory without a limit, so an attacker-controlled endpoint can exhaust the victim's RAM?

## Target
- File/function: [pkg/cmd/release/shared/fetch.go:281](pkg/cmd/release/shared/fetch.go#L281) - `fetchReleasePath`
- Entrypoint: gh release
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Serve a multi-gigabyte body from an attacker-controlled host or asset URL.
- Invariant to test: Response reads are wrapped in a limit reader with an explicit cap.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with a huge/endless body asserting a bounded error.
