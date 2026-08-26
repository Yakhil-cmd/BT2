# Q5188: repoSync.configureWorktree — submodule persistence under recursive default

## Question
Can an unprivileged attacker who gets a submodule materialised once, then removes it from `.gitmodules`, under the default `--submodules=recursive`, reach a state where — in the `submodule update --init [--recursive] [--depth N]` invocation in configureWorktree() — the stale submodule content and its `.git/modules` entry survive later syncs and stay in the published tree, breaking the invariant that removed submodules disappear from published content and yielding stale attacker content served indefinitely after removal from the repo?

## Target
- File/function: [main.go](main.go) — `repoSync.configureWorktree`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Gets a submodule materialised once, then removes it from `.gitmodules`. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the stale submodule content and its `.git/modules` entry survive later syncs and stay in the published tree
- Invariant to test: removed submodules disappear from published content
- Expected Immunefi impact: stale attacker content served indefinitely after removal from the repo (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert every materialised submodule path is inside the worktree
