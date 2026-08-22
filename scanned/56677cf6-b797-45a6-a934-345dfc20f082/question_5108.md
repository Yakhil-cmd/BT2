# Q5108: git output parsed as trusted - SmartBaseRepoFunc in default.go

## Question
Does `SmartBaseRepoFunc` in [pkg/cmd/factory/default.go](pkg/cmd/factory/default.go#L152) parse git stdout that a hostile repository can shape (branch names, remote lists, config values) and use it for a host or path decision?

## Target
- File/function: [pkg/cmd/factory/default.go:152](pkg/cmd/factory/default.go#L152) - `SmartBaseRepoFunc`
- Entrypoint: gh factory default
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish a repo whose branch names embed delimiters used by gh's parser.
- Invariant to test: Git output is parsed with NUL-delimited/porcelain formats and validated.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with delimiter-bearing names asserting correct parsing.
