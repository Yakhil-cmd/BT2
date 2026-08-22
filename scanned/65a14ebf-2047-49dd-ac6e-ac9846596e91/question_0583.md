# Q0583: git output parsed as trusted - NewCmdBrowse in browse.go

## Question
Does `NewCmdBrowse` in [pkg/cmd/browse/browse.go](pkg/cmd/browse/browse.go#L52) parse git stdout that a hostile repository can shape (branch names, remote lists, config values) and use it for a host or path decision?

## Target
- File/function: [pkg/cmd/browse/browse.go:52](pkg/cmd/browse/browse.go#L52) - `NewCmdBrowse`
- Entrypoint: gh browse browse
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish a repo whose branch names embed delimiters used by gh's parser.
- Invariant to test: Git output is parsed with NUL-delimited/porcelain formats and validated.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with delimiter-bearing names asserting correct parsing.
