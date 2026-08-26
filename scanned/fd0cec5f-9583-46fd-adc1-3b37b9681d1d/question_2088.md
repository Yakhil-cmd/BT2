# Q2088: ReRun — touch mkdirall symlink under error file

## Question
Can an unprivileged attacker who commits a symlink on the path components leading to --touch-file, under `--error-file` inside --root, read by the consumer as a health signal, reach a state where — in the PID-1 shim: re-exec of /proc/self/exe, signal forwarding, and child reaping — touch()'s MkdirAll/Create follows it and creates files outside --root, breaking the invariant that readiness-file creation is confined to --root and yielding file creation outside --root on a co-mounted volume?

## Target
- File/function: [pkg/pid1/pid1.go](pkg/pid1/pid1.go) — `ReRun / runInit / sigchld`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Commits a symlink on the path components leading to --touch-file. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: touch()'s MkdirAll/Create follows it and creates files outside --root
- Invariant to test: readiness-file creation is confined to --root
- Expected Immunefi impact: file creation outside --root on a co-mounted volume (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: break the sync deterministically and assert `/` stops returning 200 (or that the staleness is otherwise surfaced)
