# Q5350: git output parsed as trusted - updateRun in update.go

## Question
Does `updateRun` in [pkg/cmd/skills/update/update.go](pkg/cmd/skills/update/update.go#L143) parse git stdout that a hostile repository can shape (branch names, remote lists, config values) and use it for a host or path decision?

## Target
- File/function: [pkg/cmd/skills/update/update.go:143](pkg/cmd/skills/update/update.go#L143) - `updateRun`
- Entrypoint: gh skills update
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a repo whose branch names embed delimiters used by gh's parser.
- Invariant to test: Git output is parsed with NUL-delimited/porcelain formats and validated.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with delimiter-bearing names asserting correct parsing.
