# Q5854: repoSync.SetupDefaultGitConfigs — submodule off bypass under recursive default

## Question
Can an unprivileged attacker who uses gitlinks plus checked-in `.git` directories to deliver content even when `--submodules=off`, under the default `--submodules=recursive`, reach a state where — in the global git config git-sync installs before any submodule work (credential.helper cache, core.askPass true) — content the operator excluded is published anyway, breaking the invariant that `--submodules=off` means no submodule content is materialised by any path and yielding operator-excluded attacker content published to consumers?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupDefaultGitConfigs`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Uses gitlinks plus checked-in `.git` directories to deliver content even when `--submodules=off`. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: content the operator excluded is published anyway
- Invariant to test: `--submodules=off` means no submodule content is materialised by any path
- Expected Immunefi impact: operator-excluded attacker content published to consumers (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once against the fixture and assert no credential, key, or token was presented to the fixture's second host (log the server side)
