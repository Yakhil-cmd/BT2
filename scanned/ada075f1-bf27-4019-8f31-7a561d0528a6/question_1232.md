# Q1232: temporary directory predictable - NewCmdCreate in create.go

## Question
Does `NewCmdCreate` in [pkg/cmd/gist/create/create.go](pkg/cmd/gist/create/create.go#L43) stage downloads in a predictable shared temp path where another local process can substitute the content before it is used or verified?

## Target
- File/function: [pkg/cmd/gist/create/create.go:43](pkg/cmd/gist/create/create.go#L43) - `NewCmdCreate`
- Entrypoint: gh gist create
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Pre-create the predictable path before the victim runs gh gist create.
- Invariant to test: Staging uses a per-run private directory created with exclusive semantics.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting a random, 0700 staging directory.
