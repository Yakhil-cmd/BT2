# Q4833: remote resolution picks the attacker remote - FormatSlice in text.go

## Question
Can an extra remote added by an attacker-published repository be selected by `FormatSlice` in [internal/text/text.go](internal/text/text.go#L97) as the base repo, so subsequent authenticated API calls target attacker coordinates?

## Target
- File/function: [internal/text/text.go:97](internal/text/text.go#L97) - `FormatSlice`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Ship a repo containing a second remote named to win gh's resolution order.
- Invariant to test: Base repo resolution prefers explicitly configured/authenticated hosts and warns on ambiguity.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test in a temp repo with competing remotes asserting the expected selection.
