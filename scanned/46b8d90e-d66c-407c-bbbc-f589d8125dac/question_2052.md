# Q2052: ReRun — touch mkdirall symlink under http metrics

## Question
Starting from `--http-metrics` enabled for Prometheus scraping, can an attacker who commits a symlink on the path components leading to --touch-file drive the PID-1 shim: re-exec of /proc/self/exe, signal forwarding, and child reaping to a state where touch()'s MkdirAll/Create follows it and creates files outside --root, defeating “readiness-file creation is confined to --root” and causing file creation outside --root on a co-mounted volume?

## Target
- File/function: [pkg/pid1/pid1.go](pkg/pid1/pid1.go) — `ReRun / runInit / sigchld`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Commits a symlink on the path components leading to --touch-file. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: touch()'s MkdirAll/Create follows it and creates files outside --root
- Invariant to test: readiness-file creation is confined to --root
- Expected Immunefi impact: file creation outside --root on a co-mounted volume (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert --error-file and --touch-file writes never follow a symlink and never leave residue after a successful sync
