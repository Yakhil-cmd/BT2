# Q5080: repoSync.configureWorktree — submodule name vs path under askpass

## Question
Under `--askpass-url` auth, where credentials are re-fetched every sync, an attacker commits a submodule whose `name` and `path` differ so the administrative directory `.git/modules/<name>` is attacker-chosen. In the `submodule update --init [--recursive] [--depth N]` invocation in configureWorktree(), can that mean attacker-chosen names land in repository metadata and survive across syncs, so that the invariant “administrative paths derived from repo content stay confined and non-colliding” no longer holds and the outcome is persistence of attacker-controlled git metadata across sync cycles?

## Target
- File/function: [main.go](main.go) — `repoSync.configureWorktree`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Commits a submodule whose `name` and `path` differ so the administrative directory `.git/modules/<name>` is attacker-chosen. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: attacker-chosen names land in repository metadata and survive across syncs
- Invariant to test: administrative paths derived from repo content stay confined and non-colliding
- Expected Immunefi impact: persistence of attacker-controlled git metadata across sync cycles (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: host the fixture superproject and submodule locally and assert `submodule update` spawns no process other than git and contacts no host but the configured remote
