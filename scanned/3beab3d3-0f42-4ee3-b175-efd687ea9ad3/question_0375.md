# Q0375: repoSync.CallAskPassURL — cred url scope widening under password file

## Question
Starting from `--password-file`, re-read on every sync for rotation, can an attacker who arranges the effective credential URL to be broader than intended (scheme-only or host-only after redirect) drive CallAskPassURL(): the HTTP GET and the newline/`=`-split parse of the askpass response to a state where git matches the stored credential against attacker-chosen paths on the same host, defeating “credential matching is path-exact for the configured repo” and causing credential disclosure / unauthorized repository access?

## Target
- File/function: [main.go](main.go) — `repoSync.CallAskPassURL`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Arranges the effective credential URL to be broader than intended (scheme-only or host-only after redirect). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: git matches the stored credential against attacker-chosen paths on the same host
- Invariant to test: credential matching is path-exact for the configured repo
- Expected Immunefi impact: credential disclosure / unauthorized repository access (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run a local auth endpoint / fixture remote that records what it receives and assert no credential reaches any host but the configured one
