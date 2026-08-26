# Q1755: touch — touchfile signal forge under error file

## Question
Does touch()'s MkdirAll+Chtimes+Create, addUser()'s append to /etc/passwd, and sleepForever()'s terminal state stay safe when an attacker commits a file at the --touch-file path inside the published tree in `--error-file` inside --root, read by the consumer as a health signal — or can the readiness signal is satisfied by repo content rather than by a real sync, violating “readiness artifacts cannot be produced by repo content” and producing forged readiness: workload started against stale or empty data?

## Target
- File/function: [main.go](main.go) — `touch / addUser / sleepForever`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Commits a file at the --touch-file path inside the published tree. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the readiness signal is satisfied by repo content rather than by a real sync
- Invariant to test: readiness artifacts cannot be produced by repo content
- Expected Immunefi impact: forged readiness: workload started against stale or empty data (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: curl the bound port from an unauthorized context and assert nothing sensitive (argv, profiles, counters) is returned
