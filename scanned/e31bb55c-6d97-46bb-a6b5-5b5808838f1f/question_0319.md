# Q0319: repoSync.cleanup — gitmodules ext url under shared volume

## Question
Starting from a shared volume where the published tree is read by another container, can an attacker who commits `.gitmodules` with a `url = ext::sh -c <payload>` transport entry drive cleanup()/removeStaleWorktrees(), which must reclaim submodule object stores and worktrees to a state where `submodule update --init` invokes the ext transport helper, running the attacker's command inside the git-sync container, defeating “no repo-supplied string is ever executed as a command” and causing remote code execution in the git-sync container holding repo credentials?

## Target
- File/function: [main.go](main.go) — `repoSync.cleanup`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Commits `.gitmodules` with a `url = ext::sh -c <payload>` transport entry. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: `submodule update --init` invokes the ext transport helper, running the attacker's command inside the git-sync container
- Invariant to test: no repo-supplied string is ever executed as a command
- Expected Immunefi impact: remote code execution in the git-sync container holding repo credentials (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once against the fixture and assert no credential, key, or token was presented to the fixture's second host (log the server side)
