# Q3372: no size limit on downloaded content - NewCmdView in view.go

## Question
Is the download in `NewCmdView` in [pkg/cmd/gist/view/view.go](pkg/cmd/gist/view/view.go#L42) unbounded, letting an attacker-published asset fill the victim's disk or memory?

## Target
- File/function: [pkg/cmd/gist/view/view.go:42](pkg/cmd/gist/view/view.go#L42) - `NewCmdView`
- Entrypoint: gh gist view
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a huge or endlessly-streaming asset.
- Invariant to test: Downloads are bounded and report progress against a declared size.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an endless body asserting a bounded error.
