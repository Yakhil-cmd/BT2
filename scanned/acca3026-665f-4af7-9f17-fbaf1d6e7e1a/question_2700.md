# Q2700: ReRun — errorfile tempfile flood under http metrics

## Question
Under `--http-metrics` enabled for Prometheus scraping, an attacker makes errors fire on every period (any deterministic sync failure). In the PID-1 shim: re-exec of /proc/self/exe, signal forwarding, and child reaping, can that mean `tmp-err-*` tempfiles accumulate in --root when the rename or cleanup path fails, so that the invariant “one error file exists at a time regardless of failure rate” no longer holds and the outcome is volume exhaustion via inode/file accumulation?

## Target
- File/function: [pkg/pid1/pid1.go](pkg/pid1/pid1.go) — `ReRun / runInit / sigchld`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Makes errors fire on every period (any deterministic sync failure). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: `tmp-err-*` tempfiles accumulate in --root when the rename or cleanup path fails
- Invariant to test: one error file exists at a time regardless of failure rate
- Expected Immunefi impact: volume exhaustion via inode/file accumulation (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: curl the bound port from an unauthorized context and assert nothing sensitive (argv, profiles, counters) is returned
