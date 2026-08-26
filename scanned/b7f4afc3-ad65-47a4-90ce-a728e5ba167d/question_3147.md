# Q3147: repoSync.CallAskPassURL — cookie file reuse under cookie file

## Question
Can an unprivileged attacker who gets the sync to contact a second host while `http.cookiefile` is globally configured, under `--cookie-file` enabled, reach a state where — in CallAskPassURL(): the HTTP GET and the newline/`=`-split parse of the askpass response — the operator's cookie is sent to that host, breaking the invariant that cookies are scoped to the configured remote and yielding session credential disclosure?

## Target
- File/function: [main.go](main.go) — `repoSync.CallAskPassURL`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Gets the sync to contact a second host while `http.cookiefile` is globally configured. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the operator's cookie is sent to that host
- Invariant to test: cookies are scoped to the configured remote
- Expected Immunefi impact: session credential disclosure (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: grep logs and --error-file after the failure path and assert no secret or secret-derived value appears
