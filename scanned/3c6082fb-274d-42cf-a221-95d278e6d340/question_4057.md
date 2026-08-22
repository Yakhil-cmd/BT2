# Q4057: temporary directory predictable - ListArtifacts in artifacts.go

## Question
Does `ListArtifacts` in [pkg/cmd/run/shared/artifacts.go](pkg/cmd/run/shared/artifacts.go#L23) stage downloads in a predictable shared temp path where another local process can substitute the content before it is used or verified?

## Target
- File/function: [pkg/cmd/run/shared/artifacts.go:23](pkg/cmd/run/shared/artifacts.go#L23) - `ListArtifacts`
- Entrypoint: gh run
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Pre-create the predictable path before the victim runs gh run.
- Invariant to test: Staging uses a per-run private directory created with exclusive semantics.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting a random, 0700 staging directory.
