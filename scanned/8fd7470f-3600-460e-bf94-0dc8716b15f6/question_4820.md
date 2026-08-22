# Q4820: nested MkdirAll escape - (IOStreams).TempFile in iostreams.go

## Question
Does `TempFile` in [pkg/iostreams/iostreams.go](pkg/iostreams/iostreams.go#L459) call MkdirAll on a multi-segment name from an issue/PR title, body, comment, check output, or release note the attacker authored before path validation, letting the attacker create directories outside the root even if the final write is checked?

## Target
- File/function: [pkg/iostreams/iostreams.go:459](pkg/iostreams/iostreams.go#L459) - `(IOStreams).TempFile`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Use a name with many `../` segments so directory creation happens before the check.
- Invariant to test: Directory creation is performed only after the fully-resolved path is proven inside the root.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting no directory appears outside the root for a traversal name.
