# Q2640: no size limit on downloaded content - extractZipFile in zip.go

## Question
Is the download in `extractZipFile` in [internal/zip/zip.go](internal/zip/zip.go#L42) unbounded, letting an attacker-published asset fill the victim's disk or memory?

## Target
- File/function: [internal/zip/zip.go:42](internal/zip/zip.go#L42) - `extractZipFile`
- Entrypoint: gh run download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a huge or endlessly-streaming asset.
- Invariant to test: Downloads are bounded and report progress against a declared size.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an endless body asserting a bounded error.
