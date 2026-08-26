# Q0258: repoSync.StoreCredentials — cred helper scope under error file

## Question
Starting from `--error-file` inside --root, readable by the consumer, can an attacker who makes the sync touch a second host (submodule, redirect, or LFS endpoint) after credentials are cached drive StoreCredentials(): the `url=/username=/password=` blob piped into `git credential approve` to a state where `credential.helper cache --timeout 3600` replays the operator's credential to a host it was never scoped to, defeating “a stored credential is only ever offered to the URL it was stored for” and causing disclosure of repository credentials to an attacker-controlled host?

## Target
- File/function: [main.go](main.go) — `repoSync.StoreCredentials`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Makes the sync touch a second host (submodule, redirect, or LFS endpoint) after credentials are cached. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: `credential.helper cache --timeout 3600` replays the operator's credential to a host it was never scoped to
- Invariant to test: a stored credential is only ever offered to the URL it was stored for
- Expected Immunefi impact: disclosure of repository credentials to an attacker-controlled host (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: grep logs and --error-file after the failure path and assert no secret or secret-derived value appears
