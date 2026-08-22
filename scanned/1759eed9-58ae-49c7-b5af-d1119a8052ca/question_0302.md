# Q0302: git output parsed as trusted - ShortRef in discovery.go

## Question
Does `ShortRef` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L138) parse git stdout that a hostile repository can shape (branch names, remote lists, config values) and use it for a host or path decision?

## Target
- File/function: [internal/skills/discovery/discovery.go:138](internal/skills/discovery/discovery.go#L138) - `ShortRef`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a repo whose branch names embed delimiters used by gh's parser.
- Invariant to test: Git output is parsed with NUL-delimited/porcelain formats and validated.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with delimiter-bearing names asserting correct parsing.
