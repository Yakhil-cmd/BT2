# Q4981: repoSync.initRepo — submodule name vs path under ssh auth

## Question
Starting from SSH auth via `--ssh-key-file` with the default `--ssh-known-hosts=false`, can an attacker who commits a submodule whose `name` and `path` differ so the administrative directory `.git/modules/<name>` is attacker-chosen drive the origin remote that relative-path submodules resolve against, set in initRepo() to a state where attacker-chosen names land in repository metadata and survive across syncs, defeating “administrative paths derived from repo content stay confined and non-colliding” and causing persistence of attacker-controlled git metadata across sync cycles?

## Target
- File/function: [main.go](main.go) — `repoSync.initRepo`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Commits a submodule whose `name` and `path` differ so the administrative directory `.git/modules/<name>` is attacker-chosen. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: attacker-chosen names land in repository metadata and survive across syncs
- Invariant to test: administrative paths derived from repo content stay confined and non-colliding
- Expected Immunefi impact: persistence of attacker-controlled git metadata across sync cycles (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert every materialised submodule path is inside the worktree
