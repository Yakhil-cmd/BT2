# Q4308: repoSync.RefreshGitHubAppToken — stdin credential timing under askpass

## Question
Under `--askpass-url` auth, re-fetched every sync, an attacker makes `git credential approve` slow or fail while the blob is on stdin. In RefreshGitHubAppToken(): installation-token minting, expiry tracking, and credential storage, can that mean the error string returned by runWithStdin() embeds command output that can contain the credential context, and it is logged, so that the invariant “credential material never appears in error strings” no longer holds and the outcome is credential disclosure via error reporting?

## Target
- File/function: [main.go](main.go) — `repoSync.RefreshGitHubAppToken`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Makes `git credential approve` slow or fail while the blob is on stdin. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the error string returned by runWithStdin() embeds command output that can contain the credential context, and it is logged
- Invariant to test: credential material never appears in error strings
- Expected Immunefi impact: credential disclosure via error reporting (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: rotate the credential mid-sync and assert exactly one valid credential is live afterwards
