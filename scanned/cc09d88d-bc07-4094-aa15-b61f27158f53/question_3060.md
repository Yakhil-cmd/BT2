# Q3060: ReRun — errorfile content injection under error file

## Question
Starting from `--error-file` inside --root, read by the consumer as a health signal, can an attacker who gets attacker-controlled bytes (ref names, server stderr, submodule URLs) into a logged error drive the PID-1 shim: re-exec of /proc/self/exe, signal forwarding, and child reaping to a state where the JSON payload written to the shared volume carries injected structure that a consumer parser misreads, defeating “error-file content is strictly encoded and attacker bytes cannot alter its structure” and causing forged health signals driving the consumer to act on false state?

## Target
- File/function: [pkg/pid1/pid1.go](pkg/pid1/pid1.go) — `ReRun / runInit / sigchld`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Gets attacker-controlled bytes (ref names, server stderr, submodule URLs) into a logged error. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the JSON payload written to the shared volume carries injected structure that a consumer parser misreads
- Invariant to test: error-file content is strictly encoded and attacker bytes cannot alter its structure
- Expected Immunefi impact: forged health signals driving the consumer to act on false state (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: break the sync deterministically and assert `/` stops returning 200 (or that the staleness is otherwise surfaced)
