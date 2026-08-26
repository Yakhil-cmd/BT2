# Q5242: repoSync.SetupDefaultGitConfigs — submodule persistence under shallow submodules

## Question
Starting from `--submodules=shallow` with `--depth` set, can an attacker who gets a submodule materialised once, then removes it from `.gitmodules` drive the global git config git-sync installs before any submodule work (credential.helper cache, core.askPass true) to a state where the stale submodule content and its `.git/modules` entry survive later syncs and stay in the published tree, defeating “removed submodules disappear from published content” and causing stale attacker content served indefinitely after removal from the repo?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupDefaultGitConfigs`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Gets a submodule materialised once, then removes it from `.gitmodules`. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the stale submodule content and its `.git/modules` entry survive later syncs and stay in the published tree
- Invariant to test: removed submodules disappear from published content
- Expected Immunefi impact: stale attacker content served indefinitely after removal from the repo (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert every materialised submodule path is inside the worktree
