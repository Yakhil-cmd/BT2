# Q4657: remote resolution picks the attacker remote - publishRun in publish.go

## Question
Can an extra remote added by an attacker-published repository be selected by `publishRun` in [pkg/cmd/skills/publish/publish.go](pkg/cmd/skills/publish/publish.go#L168) as the base repo, so subsequent authenticated API calls target attacker coordinates?

## Target
- File/function: [pkg/cmd/skills/publish/publish.go:168](pkg/cmd/skills/publish/publish.go#L168) - `publishRun`
- Entrypoint: gh skills publish
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Ship a repo containing a second remote named to win gh's resolution order.
- Invariant to test: Base repo resolution prefers explicitly configured/authenticated hosts and warns on ambiguity.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test in a temp repo with competing remotes asserting the expected selection.
