# Q3156: repoSync.RefreshGitHubAppToken — cookie file reuse under cookie file

## Question
Under `--cookie-file` enabled, an attacker gets the sync to contact a second host while `http.cookiefile` is globally configured. In RefreshGitHubAppToken(): installation-token minting, expiry tracking, and credential storage, can that mean the operator's cookie is sent to that host, so that the invariant “cookies are scoped to the configured remote” no longer holds and the outcome is session credential disclosure?

## Target
- File/function: [main.go](main.go) — `repoSync.RefreshGitHubAppToken`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Gets the sync to contact a second host while `http.cookiefile` is globally configured. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the operator's cookie is sent to that host
- Invariant to test: cookies are scoped to the configured remote
- Expected Immunefi impact: session credential disclosure (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: rotate the credential mid-sync and assert exactly one valid credential is live afterwards
