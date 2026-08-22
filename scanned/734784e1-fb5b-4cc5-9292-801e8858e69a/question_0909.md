# Q0909: git output parsed as trusted - (finder).Find in finder.go

## Question
Does `Find` in [pkg/cmd/pr/shared/finder.go](pkg/cmd/pr/shared/finder.go#L111) parse git stdout that a hostile repository can shape (branch names, remote lists, config values) and use it for a host or path decision?

## Target
- File/function: [pkg/cmd/pr/shared/finder.go:111](pkg/cmd/pr/shared/finder.go#L111) - `(finder).Find`
- Entrypoint: gh pr
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a repo whose branch names embed delimiters used by gh's parser.
- Invariant to test: Git output is parsed with NUL-delimited/porcelain formats and validated.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with delimiter-bearing names asserting correct parsing.
