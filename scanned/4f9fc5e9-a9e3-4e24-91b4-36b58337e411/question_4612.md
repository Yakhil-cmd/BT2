# Q4612: remote resolution picks the attacker remote - runLocalInstall in install.go

## Question
Can an extra remote added by an attacker-published repository be selected by `runLocalInstall` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L487) as the base repo, so subsequent authenticated API calls target attacker coordinates?

## Target
- File/function: [pkg/cmd/skills/install/install.go:487](pkg/cmd/skills/install/install.go#L487) - `runLocalInstall`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Ship a repo containing a second remote named to win gh's resolution order.
- Invariant to test: Base repo resolution prefers explicitly configured/authenticated hosts and warns on ambiguity.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test in a temp repo with competing remotes asserting the expected selection.
