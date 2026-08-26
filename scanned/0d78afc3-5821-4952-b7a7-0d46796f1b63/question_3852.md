# Q3852: ReRun — errorfile delete race under sync on signal

## Question
Under `--sync-on-signal` configured, an attacker alternates success and failure each period. In the PID-1 shim: re-exec of /proc/self/exe, signal forwarding, and child reaping, can that mean DeleteErrorFile() and writeContent() race, leaving a stale error visible after a successful sync or no error after a failure, so that the invariant “the error file exactly reflects the last sync outcome” no longer holds and the outcome is consumers acting on an inverted health signal?

## Target
- File/function: [pkg/pid1/pid1.go](pkg/pid1/pid1.go) — `ReRun / runInit / sigchld`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Alternates success and failure each period. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: DeleteErrorFile() and writeContent() race, leaving a stale error visible after a successful sync or no error after a failure
- Invariant to test: the error file exactly reflects the last sync outcome
- Expected Immunefi impact: consumers acting on an inverted health signal (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: break the sync deterministically and assert `/` stops returning 200 (or that the staleness is otherwise surfaced)
