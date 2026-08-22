# Q0938: git output parsed as trusted - (Manager).installGit in manager.go

## Question
Does `installGit` in [pkg/cmd/extension/manager.go](pkg/cmd/extension/manager.go#L412) parse git stdout that a hostile repository can shape (branch names, remote lists, config values) and use it for a host or path decision?

## Target
- File/function: [pkg/cmd/extension/manager.go:412](pkg/cmd/extension/manager.go#L412) - `(Manager).installGit`
- Entrypoint: gh extension manager
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish a repo whose branch names embed delimiters used by gh's parser.
- Invariant to test: Git output is parsed with NUL-delimited/porcelain formats and validated.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with delimiter-bearing names asserting correct parsing.
