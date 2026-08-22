# Q4076: no size limit on downloaded content - writeTable in read_dir.go

## Question
Is the download in `writeTable` in [pkg/cmd/repo/read-dir/read_dir.go](pkg/cmd/repo/read-dir/read_dir.go#L166) unbounded, letting an attacker-published asset fill the victim's disk or memory?

## Target
- File/function: [pkg/cmd/repo/read-dir/read_dir.go:166](pkg/cmd/repo/read-dir/read_dir.go#L166) - `writeTable`
- Entrypoint: gh repo read-dir
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a huge or endlessly-streaming asset.
- Invariant to test: Downloads are bounded and report progress against a declared size.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an endless body asserting a bounded error.
