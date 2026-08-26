# Q0292: repoSync.configureWorktree — gitmodules ext url under shared volume

## Question
Can an unprivileged attacker who commits `.gitmodules` with a `url = ext::sh -c <payload>` transport entry, under a shared volume where the published tree is read by another container, reach a state where — in the `submodule update --init [--recursive] [--depth N]` invocation in configureWorktree() — `submodule update --init` invokes the ext transport helper, running the attacker's command inside the git-sync container, breaking the invariant that no repo-supplied string is ever executed as a command and yielding remote code execution in the git-sync container holding repo credentials?

## Target
- File/function: [main.go](main.go) — `repoSync.configureWorktree`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Commits `.gitmodules` with a `url = ext::sh -c <payload>` transport entry. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: `submodule update --init` invokes the ext transport helper, running the attacker's command inside the git-sync container
- Invariant to test: no repo-supplied string is ever executed as a command
- Expected Immunefi impact: remote code execution in the git-sync container holding repo credentials (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once against the fixture and assert no credential, key, or token was presented to the fixture's second host (log the server side)
