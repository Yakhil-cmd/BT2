# Q1498: repoSync.SetupDefaultGitConfigs — submodule recursion bomb under github app

## Question
Starting from GitHub App auth, where a short-lived installation token is stored as a credential, can an attacker who commits mutually recursive submodules (A includes B, B includes A) or a very deep chain drive the global git config git-sync installs before any submodule work (credential.helper cache, core.askPass true) to a state where `--recursive` update never terminates within --sync-timeout and consumes unbounded disk, defeating “recursive submodule work is depth-bounded” and causing volume exhaustion and permanent denial of updates?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupDefaultGitConfigs`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Commits mutually recursive submodules (A includes B, B includes A) or a very deep chain. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: `--recursive` update never terminates within --sync-timeout and consumes unbounded disk
- Invariant to test: recursive submodule work is depth-bounded
- Expected Immunefi impact: volume exhaustion and permanent denial of updates (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once against the fixture and assert no credential, key, or token was presented to the fixture's second host (log the server side)
