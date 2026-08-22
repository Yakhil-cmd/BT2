# Q2856: nested MkdirAll escape - setStateEntry in update.go

## Question
Does `setStateEntry` in [internal/update/update.go](internal/update/update.go#L162) call MkdirAll on a multi-segment name from an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes before path validation, letting the attacker create directories outside the root even if the final write is checked?

## Target
- File/function: [internal/update/update.go:162](internal/update/update.go#L162) - `setStateEntry`
- Entrypoint: gh alias import
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Use a name with many `../` segments so directory creation happens before the check.
- Invariant to test: Directory creation is performed only after the fully-resolved path is proven inside the root.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting no directory appears outside the root for a traversal name.
