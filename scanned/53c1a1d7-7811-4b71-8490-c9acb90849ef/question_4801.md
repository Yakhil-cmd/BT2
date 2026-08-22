# Q4801: no size limit on downloaded content - NewCmdCreate in create.go

## Question
Is the download in `NewCmdCreate` in [pkg/cmd/gist/create/create.go](pkg/cmd/gist/create/create.go#L43) unbounded, letting an attacker-published asset fill the victim's disk or memory?

## Target
- File/function: [pkg/cmd/gist/create/create.go:43](pkg/cmd/gist/create/create.go#L43) - `NewCmdCreate`
- Entrypoint: gh gist create
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a huge or endlessly-streaming asset.
- Invariant to test: Downloads are bounded and report progress against a declared size.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an endless body asserting a bounded error.
