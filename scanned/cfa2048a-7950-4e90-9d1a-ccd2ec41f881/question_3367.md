# Q3367: unbounded response body - GetRawGistFile in shared.go

## Question
Does `GetRawGistFile` in [pkg/cmd/gist/shared/shared.go](pkg/cmd/gist/shared/shared.go#L258) read the whole response body into memory without a limit, so an attacker-controlled endpoint can exhaust the victim's RAM?

## Target
- File/function: [pkg/cmd/gist/shared/shared.go:258](pkg/cmd/gist/shared/shared.go#L258) - `GetRawGistFile`
- Entrypoint: gh gist
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Serve a multi-gigabyte body from an attacker-controlled host or asset URL.
- Invariant to test: Response reads are wrapped in a limit reader with an explicit cap.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with a huge/endless body asserting a bounded error.
