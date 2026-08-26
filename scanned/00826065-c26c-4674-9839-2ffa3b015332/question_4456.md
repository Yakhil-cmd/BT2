# Q4456: repoSync.initRepo — empty repo first sync under maxfail

## Question
Does the repo bootstrap in initRepo() (`git init -b git-sync`, `remote get-url/add/set-url origin`) stay safe when an attacker makes the remote ref exist but point at an empty tree on the very first sync in a deployment with `--max-failures` set, where repeated errors terminate the container — or can initRepo()/sanityCheckRepo() treat the resulting root as invalid and wipe it, or a zero-file worktree is published as ready, violating “an empty publish is never reported as a successful, ready sync” and producing consumers served an empty dataset while readiness reports success?

## Target
- File/function: [main.go](main.go) — `repoSync.initRepo`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Makes the remote ref exist but point at an empty tree on the very first sync. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: initRepo()/sanityCheckRepo() treat the resulting root as invalid and wipe it, or a zero-file worktree is published as ready
- Invariant to test: an empty publish is never reported as a successful, ready sync
- Expected Immunefi impact: consumers served an empty dataset while readiness reports success (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: unit-test the resolution path with a fixture repo and assert the resolved hash equals `git rev-parse <ref>` on the server
