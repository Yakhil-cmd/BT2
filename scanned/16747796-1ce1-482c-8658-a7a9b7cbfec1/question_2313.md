# Q2313: main (sync loop) — errorfile symlink under http pprof

## Question
Can an unprivileged attacker who plants a symlink at the --error-file path (repo content, or a co-tenant on the shared volume), under `--http-pprof` enabled for debugging, reach a state where — in the sync loop's failCount/--max-failures handling and the one-way repoReady latch behind the `/` liveness handler — writeContent()'s rename-into-place writes error JSON through it, or DeleteErrorFile() removes the symlink target, breaking the invariant that error-file writes never follow attacker-controlled links and yielding arbitrary file overwrite/deletion outside --root?

## Target
- File/function: [main.go](main.go) — `main (sync loop) / getRepoReady / setRepoReady`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Plants a symlink at the --error-file path (repo content, or a co-tenant on the shared volume). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: writeContent()'s rename-into-place writes error JSON through it, or DeleteErrorFile() removes the symlink target
- Invariant to test: error-file writes never follow attacker-controlled links
- Expected Immunefi impact: arbitrary file overwrite/deletion outside --root (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert --error-file and --touch-file writes never follow a symlink and never leave residue after a successful sync
