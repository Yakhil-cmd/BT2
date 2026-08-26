# Q3726: Logger.Error — errorfile delete race under touch file

## Question
Can an unprivileged attacker who alternates success and failure each period, under `--touch-file` used as a readiness gate by the consumer, reach a state where — in the error-file writer: tempfile creation in --root, JSON payload marshalling, and deletion on success — DeleteErrorFile() and writeContent() race, leaving a stale error visible after a successful sync or no error after a failure, breaking the invariant that the error file exactly reflects the last sync outcome and yielding consumers acting on an inverted health signal?

## Target
- File/function: [pkg/logging/logging.go](pkg/logging/logging.go) — `Logger.Error / writeContent / ExportError / DeleteErrorFile`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Alternates success and failure each period. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: DeleteErrorFile() and writeContent() race, leaving a stale error visible after a successful sync or no error after a failure
- Invariant to test: the error file exactly reflects the last sync outcome
- Expected Immunefi impact: consumers acting on an inverted health signal (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: curl the bound port from an unauthorized context and assert nothing sensitive (argv, profiles, counters) is returned
