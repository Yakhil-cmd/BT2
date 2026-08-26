# Q1878: repoSync.StoreCredentials — github token expiry skew under error file

## Question
Can an unprivileged attacker who stalls syncs (slow remote) so the 30-second expiry margin in RefreshGitHubAppToken() is crossed mid-fetch, under `--error-file` inside --root, readable by the consumer, reach a state where — in StoreCredentials(): the `url=/username=/password=` blob piped into `git credential approve` — an expired or newly-minted token is stored while the old one is still in the helper cache, producing auth failure loops or a lingering valid token, breaking the invariant that exactly one live token is cached and it is refreshed before use and yielding denial of updates, or a valid token cached longer than its lifetime?

## Target
- File/function: [main.go](main.go) — `repoSync.StoreCredentials`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Stalls syncs (slow remote) so the 30-second expiry margin in RefreshGitHubAppToken() is crossed mid-fetch. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: an expired or newly-minted token is stored while the old one is still in the helper cache, producing auth failure loops or a lingering valid token
- Invariant to test: exactly one live token is cached and it is refreshed before use
- Expected Immunefi impact: denial of updates, or a valid token cached longer than its lifetime (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run a local auth endpoint / fixture remote that records what it receives and assert no credential reaches any host but the configured one
