# Q4769: no size limit on downloaded content - downloadArtifact in http.go

## Question
Is the download in `downloadArtifact` in [pkg/cmd/run/download/http.go](pkg/cmd/run/download/http.go#L31) unbounded, letting an attacker-published asset fill the victim's disk or memory?

## Target
- File/function: [pkg/cmd/run/download/http.go:31](pkg/cmd/run/download/http.go#L31) - `downloadArtifact`
- Entrypoint: gh run download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a huge or endlessly-streaming asset.
- Invariant to test: Downloads are bounded and report progress against a declared size.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an endless body asserting a bounded error.
