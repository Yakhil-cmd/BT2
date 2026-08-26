# Q0103: repoSync.cleanup — gitmodules ext url under submodules off

## Question
Under `--submodules=off`, where the operator believes no submodule content is fetched, an attacker commits `.gitmodules` with a `url = ext::sh -c <payload>` transport entry. In cleanup()/removeStaleWorktrees(), which must reclaim submodule object stores and worktrees, can that mean `submodule update --init` invokes the ext transport helper, running the attacker's command inside the git-sync container, so that the invariant “no repo-supplied string is ever executed as a command” no longer holds and the outcome is remote code execution in the git-sync container holding repo credentials?

## Target
- File/function: [main.go](main.go) — `repoSync.cleanup`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Commits `.gitmodules` with a `url = ext::sh -c <payload>` transport entry. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: `submodule update --init` invokes the ext transport helper, running the attacker's command inside the git-sync container
- Invariant to test: no repo-supplied string is ever executed as a command
- Expected Immunefi impact: remote code execution in the git-sync container holding repo credentials (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once against the fixture and assert no credential, key, or token was presented to the fixture's second host (log the server side)
