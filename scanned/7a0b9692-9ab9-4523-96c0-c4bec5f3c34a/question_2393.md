# Q2393: git output parsed as trusted - (gitExecuter).Fetch in git.go

## Question
Does `Fetch` in [pkg/cmd/extension/git.go](pkg/cmd/extension/git.go#L44) parse git stdout that a hostile repository can shape (branch names, remote lists, config values) and use it for a host or path decision?

## Target
- File/function: [pkg/cmd/extension/git.go:44](pkg/cmd/extension/git.go#L44) - `(gitExecuter).Fetch`
- Entrypoint: gh extension git
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish a repo whose branch names embed delimiters used by gh's parser.
- Invariant to test: Git output is parsed with NUL-delimited/porcelain formats and validated.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with delimiter-bearing names asserting correct parsing.
