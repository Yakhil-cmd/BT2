# Q0528: repoSync.RefreshGitHubAppToken — cred url scope widening under ssh known hosts

## Question
Can an unprivileged attacker who arranges the effective credential URL to be broader than intended (scheme-only or host-only after redirect), under SSH auth with `--ssh-known-hosts` and a mounted known-hosts file, reach a state where — in RefreshGitHubAppToken(): installation-token minting, expiry tracking, and credential storage — git matches the stored credential against attacker-chosen paths on the same host, breaking the invariant that credential matching is path-exact for the configured repo and yielding credential disclosure / unauthorized repository access?

## Target
- File/function: [main.go](main.go) — `repoSync.RefreshGitHubAppToken`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Arranges the effective credential URL to be broader than intended (scheme-only or host-only after redirect). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: git matches the stored credential against attacker-chosen paths on the same host
- Invariant to test: credential matching is path-exact for the configured repo
- Expected Immunefi impact: credential disclosure / unauthorized repository access (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: rotate the credential mid-sync and assert exactly one valid credential is live afterwards
