# Q1507: repoSync.cleanup — submodule recursion bomb under github app

## Question
Can an unprivileged attacker who commits mutually recursive submodules (A includes B, B includes A) or a very deep chain, under GitHub App auth, where a short-lived installation token is stored as a credential, reach a state where — in cleanup()/removeStaleWorktrees(), which must reclaim submodule object stores and worktrees — `--recursive` update never terminates within --sync-timeout and consumes unbounded disk, breaking the invariant that recursive submodule work is depth-bounded and yielding volume exhaustion and permanent denial of updates?

## Target
- File/function: [main.go](main.go) — `repoSync.cleanup`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Commits mutually recursive submodules (A includes B, B includes A) or a very deep chain. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: `--recursive` update never terminates within --sync-timeout and consumes unbounded disk
- Invariant to test: recursive submodule work is depth-bounded
- Expected Immunefi impact: volume exhaustion and permanent denial of updates (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: host the fixture superproject and submodule locally and assert `submodule update` spawns no process other than git and contacts no host but the configured remote
