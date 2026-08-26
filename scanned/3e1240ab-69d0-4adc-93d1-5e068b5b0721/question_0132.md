# Q0132: repoSync.RefreshGitHubAppToken — cred helper scope under github app

## Question
Under GitHub App auth with `--github-app-*` flags, an attacker makes the sync touch a second host (submodule, redirect, or LFS endpoint) after credentials are cached. In RefreshGitHubAppToken(): installation-token minting, expiry tracking, and credential storage, can that mean `credential.helper cache --timeout 3600` replays the operator's credential to a host it was never scoped to, so that the invariant “a stored credential is only ever offered to the URL it was stored for” no longer holds and the outcome is disclosure of repository credentials to an attacker-controlled host?

## Target
- File/function: [main.go](main.go) — `repoSync.RefreshGitHubAppToken`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Makes the sync touch a second host (submodule, redirect, or LFS endpoint) after credentials are cached. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: `credential.helper cache --timeout 3600` replays the operator's credential to a host it was never scoped to
- Invariant to test: a stored credential is only ever offered to the URL it was stored for
- Expected Immunefi impact: disclosure of repository credentials to an attacker-controlled host (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: rotate the credential mid-sync and assert exactly one valid credential is live afterwards
