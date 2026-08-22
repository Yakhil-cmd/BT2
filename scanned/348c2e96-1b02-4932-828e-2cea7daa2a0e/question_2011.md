# Q2011: remote resolution picks the attacker remote - NewCmdBrowse in browse.go

## Question
Can an extra remote added by an attacker-published repository be selected by `NewCmdBrowse` in [pkg/cmd/browse/browse.go](pkg/cmd/browse/browse.go#L52) as the base repo, so subsequent authenticated API calls target attacker coordinates?

## Target
- File/function: [pkg/cmd/browse/browse.go:52](pkg/cmd/browse/browse.go#L52) - `NewCmdBrowse`
- Entrypoint: gh browse browse
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Ship a repo containing a second remote named to win gh's resolution order.
- Invariant to test: Base repo resolution prefers explicitly configured/authenticated hosts and warns on ambiguity.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test in a temp repo with competing remotes asserting the expected selection.
