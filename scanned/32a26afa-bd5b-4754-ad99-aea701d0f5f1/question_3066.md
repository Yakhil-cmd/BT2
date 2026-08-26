# Q3066: repoSync.StoreCredentials — cookie file reuse under ssh default

## Question
Under SSH auth with the default `--ssh-known-hosts=false`, an attacker gets the sync to contact a second host while `http.cookiefile` is globally configured. In StoreCredentials(): the `url=/username=/password=` blob piped into `git credential approve`, can that mean the operator's cookie is sent to that host, so that the invariant “cookies are scoped to the configured remote” no longer holds and the outcome is session credential disclosure?

## Target
- File/function: [main.go](main.go) — `repoSync.StoreCredentials`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Gets the sync to contact a second host while `http.cookiefile` is globally configured. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the operator's cookie is sent to that host
- Invariant to test: cookies are scoped to the configured remote
- Expected Immunefi impact: session credential disclosure (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: grep logs and --error-file after the failure path and assert no secret or secret-derived value appears
