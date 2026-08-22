# Q2248: no size limit on downloaded content - (Absolute).Join in absolute.go

## Question
Is the download in `Join` in [internal/safepaths/absolute.go](internal/safepaths/absolute.go#L38) unbounded, letting an attacker-published asset fill the victim's disk or memory?

## Target
- File/function: [internal/safepaths/absolute.go:38](internal/safepaths/absolute.go#L38) - `(Absolute).Join`
- Entrypoint: gh run download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a huge or endlessly-streaming asset.
- Invariant to test: Downloads are bounded and report progress against a declared size.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an endless body asserting a bounded error.
