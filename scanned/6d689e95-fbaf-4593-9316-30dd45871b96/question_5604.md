# Q5604: repoSync.RefreshGitHubAppToken — cred in repo url under askpass

## Question
Under `--askpass-url` auth, re-fetched every sync, an attacker influences the repo URL form (user info in --repo) so the merge logic strips and re-adds credentials. In RefreshGitHubAppToken(): installation-token minting, expiry tracking, and credential storage, can that mean the credential lands in a stored credential record whose URL is logged unredacted somewhere, so that the invariant “credential extraction from the URL never widens exposure” no longer holds and the outcome is credential disclosure?

## Target
- File/function: [main.go](main.go) — `repoSync.RefreshGitHubAppToken`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Influences the repo URL form (user info in --repo) so the merge logic strips and re-adds credentials. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the credential lands in a stored credential record whose URL is logged unredacted somewhere
- Invariant to test: credential extraction from the URL never widens exposure
- Expected Immunefi impact: credential disclosure (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run a local auth endpoint / fixture remote that records what it receives and assert no credential reaches any host but the configured one
