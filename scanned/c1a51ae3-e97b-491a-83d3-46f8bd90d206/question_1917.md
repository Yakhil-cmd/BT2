# Q1917: git output parsed as trusted - populateLogSegments in logs.go

## Question
Does `populateLogSegments` in [pkg/cmd/run/view/logs.go](pkg/cmd/run/view/logs.go#L95) parse git stdout that a hostile repository can shape (branch names, remote lists, config values) and use it for a host or path decision?

## Target
- File/function: [pkg/cmd/run/view/logs.go:95](pkg/cmd/run/view/logs.go#L95) - `populateLogSegments`
- Entrypoint: gh run view
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a repo whose branch names embed delimiters used by gh's parser.
- Invariant to test: Git output is parsed with NUL-delimited/porcelain formats and validated.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with delimiter-bearing names asserting correct parsing.
