# Q5341: repoSync.initRepo — submodule persistence under http auth

## Question
Under HTTPS auth with `--username`/`$GITSYNC_PASSWORD` cached by `credential.helper cache`, an attacker gets a submodule materialised once, then removes it from `.gitmodules`. In the origin remote that relative-path submodules resolve against, set in initRepo(), can that mean the stale submodule content and its `.git/modules` entry survive later syncs and stay in the published tree, so that the invariant “removed submodules disappear from published content” no longer holds and the outcome is stale attacker content served indefinitely after removal from the repo?

## Target
- File/function: [main.go](main.go) — `repoSync.initRepo`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Gets a submodule materialised once, then removes it from `.gitmodules`. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the stale submodule content and its `.git/modules` entry survive later syncs and stay in the published tree
- Invariant to test: removed submodules disappear from published content
- Expected Immunefi impact: stale attacker content served indefinitely after removal from the repo (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: host the fixture superproject and submodule locally and assert `submodule update` spawns no process other than git and contacts no host but the configured remote
