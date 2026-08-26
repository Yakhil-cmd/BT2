# Q1854: Logger.Error — touchfile signal forge under onetime

## Question
Can an unprivileged attacker who commits a file at the --touch-file path inside the published tree, under `--one-time` mode used as an init container, reach a state where — in the error-file writer: tempfile creation in --root, JSON payload marshalling, and deletion on success — the readiness signal is satisfied by repo content rather than by a real sync, breaking the invariant that readiness artifacts cannot be produced by repo content and yielding forged readiness: workload started against stale or empty data?

## Target
- File/function: [pkg/logging/logging.go](pkg/logging/logging.go) — `Logger.Error / writeContent / ExportError / DeleteErrorFile`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Commits a file at the --touch-file path inside the published tree. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the readiness signal is satisfied by repo content rather than by a real sync
- Invariant to test: readiness artifacts cannot be produced by repo content
- Expected Immunefi impact: forged readiness: workload started against stale or empty data (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: break the sync deterministically and assert `/` stops returning 200 (or that the staleness is otherwise surfaced)
