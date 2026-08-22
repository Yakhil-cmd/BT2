# Q5492: URL parsed twice with different results - truncateAsUTF16 in logs.go

## Question
Does `truncateAsUTF16` in [pkg/cmd/run/view/logs.go](pkg/cmd/run/view/logs.go#L342) parse the same attacker string with two different parsers (url.Parse vs manual split vs git URL parser) so validation and use disagree?

## Target
- File/function: [pkg/cmd/run/view/logs.go:342](pkg/cmd/run/view/logs.go#L342) - `truncateAsUTF16`
- Entrypoint: gh run view
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Craft a URL that the two parsers read differently (`https://a@b/`, `ssh://`, `git@host:path`).
- Invariant to test: One parse result is computed once and reused for both the check and the action.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Differential fuzz test comparing both parsers on random URLs.
