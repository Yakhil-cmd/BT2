# Q1421: nested MkdirAll escape - (Context).LocalPublicKeys in ssh_keys.go

## Question
Does `LocalPublicKeys` in [pkg/ssh/ssh_keys.go](pkg/ssh/ssh_keys.go#L37) call MkdirAll on a multi-segment name from an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes before path validation, letting the attacker create directories outside the root even if the final write is checked?

## Target
- File/function: [pkg/ssh/ssh_keys.go:37](pkg/ssh/ssh_keys.go#L37) - `(Context).LocalPublicKeys`
- Entrypoint: gh alias import
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Use a name with many `../` segments so directory creation happens before the check.
- Invariant to test: Directory creation is performed only after the fully-resolved path is proven inside the root.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting no directory appears outside the root for a traversal name.
