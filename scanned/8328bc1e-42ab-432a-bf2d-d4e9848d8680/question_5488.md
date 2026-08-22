# Q5488: no size limit on downloaded content - getJobNameForLogFilename in logs.go

## Question
Is the download in `getJobNameForLogFilename` in [pkg/cmd/run/view/logs.go](pkg/cmd/run/view/logs.go#L246) unbounded, letting an attacker-published asset fill the victim's disk or memory?

## Target
- File/function: [pkg/cmd/run/view/logs.go:246](pkg/cmd/run/view/logs.go#L246) - `getJobNameForLogFilename`
- Entrypoint: gh run view
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a huge or endlessly-streaming asset.
- Invariant to test: Downloads are bounded and report progress against a declared size.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an endless body asserting a bounded error.
