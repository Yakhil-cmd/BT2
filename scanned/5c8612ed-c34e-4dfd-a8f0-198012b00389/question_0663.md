# Q0663: repoSync.CallAskPassURL — askpass response injection under http basic

## Question
Starting from HTTPS auth with `--username` and `$GITSYNC_PASSWORD`, can an attacker who controls or influences the askpass response body (attacker-run endpoint reached via redirect, or response reflection) drive CallAskPassURL(): the HTTP GET and the newline/`=`-split parse of the askpass response to a state where the naive newline/`=` split lets an injected `password=` line or embedded newline overwrite the real credential or inject extra credential fields, defeating “the askpass response is parsed as a strict, complete credential record” and causing credential substitution: git-sync authenticates to, or leaks to, an attacker-chosen target?

## Target
- File/function: [main.go](main.go) — `repoSync.CallAskPassURL`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Controls or influences the askpass response body (attacker-run endpoint reached via redirect, or response reflection). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the naive newline/`=` split lets an injected `password=` line or embedded newline overwrite the real credential or inject extra credential fields
- Invariant to test: the askpass response is parsed as a strict, complete credential record
- Expected Immunefi impact: credential substitution: git-sync authenticates to, or leaks to, an attacker-chosen target (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run a local auth endpoint / fixture remote that records what it receives and assert no credential reaches any host but the configured one
