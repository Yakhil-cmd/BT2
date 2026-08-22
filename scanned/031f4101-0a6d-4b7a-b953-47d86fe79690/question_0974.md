# Q0974: nested MkdirAll escape - makeSymlink in symlink_windows.go

## Question
Does `makeSymlink` in [pkg/cmd/extension/symlink_windows.go](pkg/cmd/extension/symlink_windows.go#L5) call MkdirAll on a multi-segment name from an extension repository, its release assets, and its manifest fields before path validation, letting the attacker create directories outside the root even if the final write is checked?

## Target
- File/function: [pkg/cmd/extension/symlink_windows.go:5](pkg/cmd/extension/symlink_windows.go#L5) - `makeSymlink`
- Entrypoint: gh extension symlink
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Use a name with many `../` segments so directory creation happens before the check.
- Invariant to test: Directory creation is performed only after the fully-resolved path is proven inside the root.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting no directory appears outside the root for a traversal name.
