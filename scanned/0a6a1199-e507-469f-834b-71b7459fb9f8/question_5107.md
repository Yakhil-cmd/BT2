# Q5107: repoSync.cleanup — submodule name vs path under askpass

## Question
Can an unprivileged attacker who commits a submodule whose `name` and `path` differ so the administrative directory `.git/modules/<name>` is attacker-chosen, under `--askpass-url` auth, where credentials are re-fetched every sync, reach a state where — in cleanup()/removeStaleWorktrees(), which must reclaim submodule object stores and worktrees — attacker-chosen names land in repository metadata and survive across syncs, breaking the invariant that administrative paths derived from repo content stay confined and non-colliding and yielding persistence of attacker-controlled git metadata across sync cycles?

## Target
- File/function: [main.go](main.go) — `repoSync.cleanup`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Commits a submodule whose `name` and `path` differ so the administrative directory `.git/modules/<name>` is attacker-chosen. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: attacker-chosen names land in repository metadata and survive across syncs
- Invariant to test: administrative paths derived from repo content stay confined and non-colliding
- Expected Immunefi impact: persistence of attacker-controlled git metadata across sync cycles (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: host the fixture superproject and submodule locally and assert `submodule update` spawns no process other than git and contacts no host but the configured remote
