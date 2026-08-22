# Q3799: nested MkdirAll escape - (Manager).Remove in manager.go

## Question
Does `Remove` in [pkg/cmd/extension/manager.go](pkg/cmd/extension/manager.go#L578) call MkdirAll on a multi-segment name from an extension repository, its release assets, and its manifest fields before path validation, letting the attacker create directories outside the root even if the final write is checked?

## Target
- File/function: [pkg/cmd/extension/manager.go:578](pkg/cmd/extension/manager.go#L578) - `(Manager).Remove`
- Entrypoint: gh extension manager
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Use a name with many `../` segments so directory creation happens before the check.
- Invariant to test: Directory creation is performed only after the fully-resolved path is proven inside the root.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting no directory appears outside the root for a traversal name.
