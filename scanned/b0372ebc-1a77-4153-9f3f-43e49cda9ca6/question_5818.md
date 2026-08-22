# Q5818: git output parsed as trusted - NewCmdClone in clone.go

## Question
Does `NewCmdClone` in [pkg/cmd/repo/clone/clone.go](pkg/cmd/repo/clone/clone.go#L33) parse git stdout that a hostile repository can shape (branch names, remote lists, config values) and use it for a host or path decision?

## Target
- File/function: [pkg/cmd/repo/clone/clone.go:33](pkg/cmd/repo/clone/clone.go#L33) - `NewCmdClone`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a repo whose branch names embed delimiters used by gh's parser.
- Invariant to test: Git output is parsed with NUL-delimited/porcelain formats and validated.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with delimiter-bearing names asserting correct parsing.
