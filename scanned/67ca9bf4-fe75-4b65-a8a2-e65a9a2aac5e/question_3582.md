# Q3582: Logger.Error — errorfile delete race under http bind

## Question
Can an unprivileged attacker who alternates success and failure each period, under a deployment with `--http-bind` reachable from other pods in the cluster, reach a state where — in the error-file writer: tempfile creation in --root, JSON payload marshalling, and deletion on success — DeleteErrorFile() and writeContent() race, leaving a stale error visible after a successful sync or no error after a failure, breaking the invariant that the error file exactly reflects the last sync outcome and yielding consumers acting on an inverted health signal?

## Target
- File/function: [pkg/logging/logging.go](pkg/logging/logging.go) — `Logger.Error / writeContent / ExportError / DeleteErrorFile`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Alternates success and failure each period. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: DeleteErrorFile() and writeContent() race, leaving a stale error visible after a successful sync or no error after a failure
- Invariant to test: the error file exactly reflects the last sync outcome
- Expected Immunefi impact: consumers acting on an inverted health signal (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: break the sync deterministically and assert `/` stops returning 200 (or that the staleness is otherwise surfaced)
