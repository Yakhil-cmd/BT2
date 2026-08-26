# Q0420: repoSync.RefreshGitHubAppToken — cred url scope widening under askpass

## Question
Under `--askpass-url` auth, re-fetched every sync, an attacker arranges the effective credential URL to be broader than intended (scheme-only or host-only after redirect). In RefreshGitHubAppToken(): installation-token minting, expiry tracking, and credential storage, can that mean git matches the stored credential against attacker-chosen paths on the same host, so that the invariant “credential matching is path-exact for the configured repo” no longer holds and the outcome is credential disclosure / unauthorized repository access?

## Target
- File/function: [main.go](main.go) — `repoSync.RefreshGitHubAppToken`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Arranges the effective credential URL to be broader than intended (scheme-only or host-only after redirect). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: git matches the stored credential against attacker-chosen paths on the same host
- Invariant to test: credential matching is path-exact for the configured repo
- Expected Immunefi impact: credential disclosure / unauthorized repository access (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: rotate the credential mid-sync and assert exactly one valid credential is live afterwards
