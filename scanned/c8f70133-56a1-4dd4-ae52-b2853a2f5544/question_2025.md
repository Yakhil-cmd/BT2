# Q2025: main (sync loop) — touch mkdirall symlink under http metrics

## Question
Can an unprivileged attacker who commits a symlink on the path components leading to --touch-file, under `--http-metrics` enabled for Prometheus scraping, reach a state where — in the sync loop's failCount/--max-failures handling and the one-way repoReady latch behind the `/` liveness handler — touch()'s MkdirAll/Create follows it and creates files outside --root, breaking the invariant that readiness-file creation is confined to --root and yielding file creation outside --root on a co-mounted volume?

## Target
- File/function: [main.go](main.go) — `main (sync loop) / getRepoReady / setRepoReady`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Commits a symlink on the path components leading to --touch-file. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: touch()'s MkdirAll/Create follows it and creates files outside --root
- Invariant to test: readiness-file creation is confined to --root
- Expected Immunefi impact: file creation outside --root on a co-mounted volume (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert --error-file and --touch-file writes never follow a symlink and never leave residue after a successful sync
