# Q4551: repoSync.CallAskPassURL — password file rotation under http basic

## Question
Starting from HTTPS auth with `--username` and `$GITSYNC_PASSWORD`, can an attacker who times a sync against password-file rotation so a partially-written file is read drive CallAskPassURL(): the HTTP GET and the newline/`=`-split parse of the askpass response to a state where a truncated password is stored and every later fetch fails, tripping --max-failures, defeating “credential reads are atomic with respect to rotation” and causing denial of updates / container crash loop?

## Target
- File/function: [main.go](main.go) — `repoSync.CallAskPassURL`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Times a sync against password-file rotation so a partially-written file is read. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: a truncated password is stored and every later fetch fails, tripping --max-failures
- Invariant to test: credential reads are atomic with respect to rotation
- Expected Immunefi impact: denial of updates / container crash loop (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run a local auth endpoint / fixture remote that records what it receives and assert no credential reaches any host but the configured one
