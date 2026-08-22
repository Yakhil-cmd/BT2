# Q4800: temporary directory predictable - viewRun in view.go

## Question
Does `viewRun` in [pkg/cmd/gist/view/view.go](pkg/cmd/gist/view/view.go#L81) stage downloads in a predictable shared temp path where another local process can substitute the content before it is used or verified?

## Target
- File/function: [pkg/cmd/gist/view/view.go:81](pkg/cmd/gist/view/view.go#L81) - `viewRun`
- Entrypoint: gh gist view
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Pre-create the predictable path before the victim runs gh gist view.
- Invariant to test: Staging uses a per-run private directory created with exclusive semantics.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting a random, 0700 staging directory.
