# Q5920: URL parsed twice with different results - Parse in frontmatter.go

## Question
Does `Parse` in [internal/skills/frontmatter/frontmatter.go](internal/skills/frontmatter/frontmatter.go#L31) parse the same attacker string with two different parsers (url.Parse vs manual split vs git URL parser) so validation and use disagree?

## Target
- File/function: [internal/skills/frontmatter/frontmatter.go:31](internal/skills/frontmatter/frontmatter.go#L31) - `Parse`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Craft a URL that the two parsers read differently (`https://a@b/`, `ssh://`, `git@host:path`).
- Invariant to test: One parse result is computed once and reused for both the check and the action.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Differential fuzz test comparing both parsers on random URLs.
