# Q0253: unbounded response body - repoExists in http.go

## Question
Does `repoExists` in [pkg/cmd/extension/http.go](pkg/cmd/extension/http.go#L16) read the whole response body into memory without a limit, so an attacker-controlled endpoint can exhaust the victim's RAM?

## Target
- File/function: [pkg/cmd/extension/http.go:16](pkg/cmd/extension/http.go#L16) - `repoExists`
- Entrypoint: gh extension http
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Serve a multi-gigabyte body from an attacker-controlled host or asset URL.
- Invariant to test: Response reads are wrapped in a limit reader with an explicit cap.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with a huge/endless body asserting a bounded error.
