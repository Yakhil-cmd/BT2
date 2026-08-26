# Q1989: main (sync loop) — touch mkdirall symlink under http pprof

## Question
Starting from `--http-pprof` enabled for debugging, can an attacker who commits a symlink on the path components leading to --touch-file drive the sync loop's failCount/--max-failures handling and the one-way repoReady latch behind the `/` liveness handler to a state where touch()'s MkdirAll/Create follows it and creates files outside --root, defeating “readiness-file creation is confined to --root” and causing file creation outside --root on a co-mounted volume?

## Target
- File/function: [main.go](main.go) — `main (sync loop) / getRepoReady / setRepoReady`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Commits a symlink on the path components leading to --touch-file. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: touch()'s MkdirAll/Create follows it and creates files outside --root
- Invariant to test: readiness-file creation is confined to --root
- Expected Immunefi impact: file creation outside --root on a co-mounted volume (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: curl the bound port from an unauthorized context and assert nothing sensitive (argv, profiles, counters) is returned
