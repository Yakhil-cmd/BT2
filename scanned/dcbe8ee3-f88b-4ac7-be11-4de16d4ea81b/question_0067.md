# Q0067: repoSync.cleanup — gitmodules ext url under shallow submodules

## Question
Can an unprivileged attacker who commits `.gitmodules` with a `url = ext::sh -c <payload>` transport entry, under `--submodules=shallow` with `--depth` set, reach a state where — in cleanup()/removeStaleWorktrees(), which must reclaim submodule object stores and worktrees — `submodule update --init` invokes the ext transport helper, running the attacker's command inside the git-sync container, breaking the invariant that no repo-supplied string is ever executed as a command and yielding remote code execution in the git-sync container holding repo credentials?

## Target
- File/function: [main.go](main.go) — `repoSync.cleanup`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Commits `.gitmodules` with a `url = ext::sh -c <payload>` transport entry. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: `submodule update --init` invokes the ext transport helper, running the attacker's command inside the git-sync container
- Invariant to test: no repo-supplied string is ever executed as a command
- Expected Immunefi impact: remote code execution in the git-sync container holding repo credentials (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert every materialised submodule path is inside the worktree
