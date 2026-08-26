# Q2823: repoSync.CallAskPassURL — known hosts off default under cookie file

## Question
Starting from `--cookie-file` enabled, can an attacker who redirects a submodule or the fetch to an attacker-controlled ssh host drive CallAskPassURL(): the HTTP GET and the newline/`=`-split parse of the askpass response to a state where the default `StrictHostKeyChecking=no` accepts it and the mounted key is offered, defeating “the mounted identity is only offered to verified hosts” and causing SSH key abuse against an attacker-chosen server?

## Target
- File/function: [main.go](main.go) — `repoSync.CallAskPassURL`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Redirects a submodule or the fetch to an attacker-controlled ssh host. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the default `StrictHostKeyChecking=no` accepts it and the mounted key is offered
- Invariant to test: the mounted identity is only offered to verified hosts
- Expected Immunefi impact: SSH key abuse against an attacker-chosen server (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run a local auth endpoint / fixture remote that records what it receives and assert no credential reaches any host but the configured one
