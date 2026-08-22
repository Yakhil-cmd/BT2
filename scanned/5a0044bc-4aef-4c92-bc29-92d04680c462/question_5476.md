# Q5476: nested MkdirAll escape - (destinationWriter).makePath in download.go

## Question
Does `makePath` in [pkg/cmd/release/download/download.go](pkg/cmd/release/download/download.go#L379) call MkdirAll on a multi-segment name from an asset, artifact, gist, or archive-member name and its bytes before path validation, letting the attacker create directories outside the root even if the final write is checked?

## Target
- File/function: [pkg/cmd/release/download/download.go:379](pkg/cmd/release/download/download.go#L379) - `(destinationWriter).makePath`
- Entrypoint: gh release download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Use a name with many `../` segments so directory creation happens before the check.
- Invariant to test: Directory creation is performed only after the fully-resolved path is proven inside the root.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting no directory appears outside the root for a traversal name.
