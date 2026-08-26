# Q0040: repoSync.configureWorktree — gitmodules ext url under shallow submodules

## Question
Under `--submodules=shallow` with `--depth` set, an attacker commits `.gitmodules` with a `url = ext::sh -c <payload>` transport entry. In the `submodule update --init [--recursive] [--depth N]` invocation in configureWorktree(), can that mean `submodule update --init` invokes the ext transport helper, running the attacker's command inside the git-sync container, so that the invariant “no repo-supplied string is ever executed as a command” no longer holds and the outcome is remote code execution in the git-sync container holding repo credentials?

## Target
- File/function: [main.go](main.go) — `repoSync.configureWorktree`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Commits `.gitmodules` with a `url = ext::sh -c <payload>` transport entry. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: `submodule update --init` invokes the ext transport helper, running the attacker's command inside the git-sync container
- Invariant to test: no repo-supplied string is ever executed as a command
- Expected Immunefi impact: remote code execution in the git-sync container holding repo credentials (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert every materialised submodule path is inside the worktree
