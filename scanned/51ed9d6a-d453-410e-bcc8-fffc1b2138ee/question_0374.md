# Q0374: git output parsed as trusted - publishRun in publish.go

## Question
Does `publishRun` in [pkg/cmd/skills/publish/publish.go](pkg/cmd/skills/publish/publish.go#L168) parse git stdout that a hostile repository can shape (branch names, remote lists, config values) and use it for a host or path decision?

## Target
- File/function: [pkg/cmd/skills/publish/publish.go:168](pkg/cmd/skills/publish/publish.go#L168) - `publishRun`
- Entrypoint: gh skills publish
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a repo whose branch names embed delimiters used by gh's parser.
- Invariant to test: Git output is parsed with NUL-delimited/porcelain formats and validated.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with delimiter-bearing names asserting correct parsing.
