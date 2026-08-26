# Q5071: repoSync.cleanup — submodule name vs path under github app

## Question
Starting from GitHub App auth, where a short-lived installation token is stored as a credential, can an attacker who commits a submodule whose `name` and `path` differ so the administrative directory `.git/modules/<name>` is attacker-chosen drive cleanup()/removeStaleWorktrees(), which must reclaim submodule object stores and worktrees to a state where attacker-chosen names land in repository metadata and survive across syncs, defeating “administrative paths derived from repo content stay confined and non-colliding” and causing persistence of attacker-controlled git metadata across sync cycles?

## Target
- File/function: [main.go](main.go) — `repoSync.cleanup`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Commits a submodule whose `name` and `path` differ so the administrative directory `.git/modules/<name>` is attacker-chosen. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: attacker-chosen names land in repository metadata and survive across syncs
- Invariant to test: administrative paths derived from repo content stay confined and non-colliding
- Expected Immunefi impact: persistence of attacker-controlled git metadata across sync cycles (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once against the fixture and assert no credential, key, or token was presented to the fixture's second host (log the server side)
