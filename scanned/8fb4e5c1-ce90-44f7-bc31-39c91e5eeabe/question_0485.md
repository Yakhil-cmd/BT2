# Q0485: no size limit on downloaded content - isolateArtifacts in download.go

## Question
Is the download in `isolateArtifacts` in [pkg/cmd/run/download/download.go](pkg/cmd/run/download/download.go#L205) unbounded, letting an attacker-published asset fill the victim's disk or memory?

## Target
- File/function: [pkg/cmd/run/download/download.go:205](pkg/cmd/run/download/download.go#L205) - `isolateArtifacts`
- Entrypoint: gh run download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a huge or endlessly-streaming asset.
- Invariant to test: Downloads are bounded and report progress against a declared size.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an endless body asserting a bounded error.
