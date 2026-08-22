# Q3358: temporary directory predictable - writeToOutput in read_file.go

## Question
Does `writeToOutput` in [pkg/cmd/repo/read-file/read_file.go](pkg/cmd/repo/read-file/read_file.go#L261) stage downloads in a predictable shared temp path where another local process can substitute the content before it is used or verified?

## Target
- File/function: [pkg/cmd/repo/read-file/read_file.go:261](pkg/cmd/repo/read-file/read_file.go#L261) - `writeToOutput`
- Entrypoint: gh repo read-file
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Pre-create the predictable path before the victim runs gh repo read-file.
- Invariant to test: Staging uses a per-run private directory created with exclusive semantics.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting a random, 0700 staging directory.
