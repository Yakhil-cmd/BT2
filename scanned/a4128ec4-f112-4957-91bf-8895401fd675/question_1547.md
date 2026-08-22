# Q1547: remote resolution picks the attacker remote - branchFunc in default.go

## Question
Can an extra remote added by an attacker-published repository be selected by `branchFunc` in [pkg/cmd/factory/default.go](pkg/cmd/factory/default.go#L262) as the base repo, so subsequent authenticated API calls target attacker coordinates?

## Target
- File/function: [pkg/cmd/factory/default.go:262](pkg/cmd/factory/default.go#L262) - `branchFunc`
- Entrypoint: gh factory default
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Ship a repo containing a second remote named to win gh's resolution order.
- Invariant to test: Base repo resolution prefers explicitly configured/authenticated hosts and warns on ambiguity.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test in a temp repo with competing remotes asserting the expected selection.
