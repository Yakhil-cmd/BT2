# Q4434: remote resolution picks the attacker remote - ParseRemoteTrackingRef in client.go

## Question
Can an extra remote added by an attacker-published repository be selected by `ParseRemoteTrackingRef` in [git/client.go](git/client.go#L604) as the base repo, so subsequent authenticated API calls target attacker coordinates?

## Target
- File/function: [git/client.go:604](git/client.go#L604) - `ParseRemoteTrackingRef`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Ship a repo containing a second remote named to win gh's resolution order.
- Invariant to test: Base repo resolution prefers explicitly configured/authenticated hosts and warns on ambiguity.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test in a temp repo with competing remotes asserting the expected selection.
