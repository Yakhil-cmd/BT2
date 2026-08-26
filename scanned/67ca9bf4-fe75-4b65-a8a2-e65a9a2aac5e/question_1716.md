# Q1716: repoSync.RefreshGitHubAppToken — github token expiry skew under askpass

## Question
Under `--askpass-url` auth, re-fetched every sync, an attacker stalls syncs (slow remote) so the 30-second expiry margin in RefreshGitHubAppToken() is crossed mid-fetch. In RefreshGitHubAppToken(): installation-token minting, expiry tracking, and credential storage, can that mean an expired or newly-minted token is stored while the old one is still in the helper cache, producing auth failure loops or a lingering valid token, so that the invariant “exactly one live token is cached and it is refreshed before use” no longer holds and the outcome is denial of updates, or a valid token cached longer than its lifetime?

## Target
- File/function: [main.go](main.go) — `repoSync.RefreshGitHubAppToken`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Stalls syncs (slow remote) so the 30-second expiry margin in RefreshGitHubAppToken() is crossed mid-fetch. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: an expired or newly-minted token is stored while the old one is still in the helper cache, producing auth failure loops or a lingering valid token
- Invariant to test: exactly one live token is cached and it is refreshed before use
- Expected Immunefi impact: denial of updates, or a valid token cached longer than its lifetime (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run a local auth endpoint / fixture remote that records what it receives and assert no credential reaches any host but the configured one
