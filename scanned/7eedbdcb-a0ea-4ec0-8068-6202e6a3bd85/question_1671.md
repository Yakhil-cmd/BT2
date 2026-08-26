# Q1671: repoSync.CallAskPassURL — github token expiry skew under password file

## Question
Starting from `--password-file`, re-read on every sync for rotation, can an attacker who stalls syncs (slow remote) so the 30-second expiry margin in RefreshGitHubAppToken() is crossed mid-fetch drive CallAskPassURL(): the HTTP GET and the newline/`=`-split parse of the askpass response to a state where an expired or newly-minted token is stored while the old one is still in the helper cache, producing auth failure loops or a lingering valid token, defeating “exactly one live token is cached and it is refreshed before use” and causing denial of updates, or a valid token cached longer than its lifetime?

## Target
- File/function: [main.go](main.go) — `repoSync.CallAskPassURL`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Stalls syncs (slow remote) so the 30-second expiry margin in RefreshGitHubAppToken() is crossed mid-fetch. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: an expired or newly-minted token is stored while the old one is still in the helper cache, producing auth failure loops or a lingering valid token
- Invariant to test: exactly one live token is cached and it is refreshed before use
- Expected Immunefi impact: denial of updates, or a valid token cached longer than its lifetime (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: grep logs and --error-file after the failure path and assert no secret or secret-derived value appears
