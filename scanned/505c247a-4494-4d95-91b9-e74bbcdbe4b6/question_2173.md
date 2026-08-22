# Q2173: nested MkdirAll escape - HomeDirPath in config.go

## Question
Does `HomeDirPath` in [internal/config/config.go](internal/config/config.go#L702) call MkdirAll on a multi-segment name from a hostname, OAuth/device response, or git credential-protocol input the attacker supplies before path validation, letting the attacker create directories outside the root even if the final write is checked?

## Target
- File/function: [internal/config/config.go:702](internal/config/config.go#L702) - `HomeDirPath`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Use a name with many `../` segments so directory creation happens before the check.
- Invariant to test: Directory creation is performed only after the fully-resolved path is proven inside the root.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting no directory appears outside the root for a traversal name.
