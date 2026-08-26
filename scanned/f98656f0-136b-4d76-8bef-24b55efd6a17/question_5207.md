# Q5207: removeDirContentsIf — reflog expire cost under gc auto

## Question
Does removeDirContentsIf(): the os.Stat + predicate + `os.RemoveAll` loop that wipes directory contents stay safe when an attacker pushes enough refs to make `reflog expire --all` take longer than the period in the default `--git-gc=auto` — or can cleanup consumes the whole period, starving fetch and publish, violating “maintenance cannot starve the sync loop” and producing permanent denial of updates?

## Target
- File/function: [main.go](main.go) — `removeDirContentsIf / removeDirContents`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Pushes enough refs to make `reflog expire --all` take longer than the period. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: cleanup consumes the whole period, starving fetch and publish
- Invariant to test: maintenance cannot starve the sync loop
- Expected Immunefi impact: permanent denial of updates (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run several periods against the fixture and assert --root file count and byte size stay bounded
