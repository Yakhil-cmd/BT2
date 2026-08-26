# Q5022: Logger.Error — pprof cpu dos under touch file

## Question
Can an unprivileged attacker who repeatedly requests `/debug/pprof/profile` and `/trace` with long durations, under `--touch-file` used as a readiness gate by the consumer, reach a state where — in the error-file writer: tempfile creation in --root, JSON payload marshalling, and deletion on success — profiling pins CPU and stalls the sync loop for the duration, breaking the invariant that diagnostic endpoints cannot starve the sync loop and yielding denial of updates via an unauthenticated endpoint?

## Target
- File/function: [pkg/logging/logging.go](pkg/logging/logging.go) — `Logger.Error / writeContent / ExportError / DeleteErrorFile`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Repeatedly requests `/debug/pprof/profile` and `/trace` with long durations. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: profiling pins CPU and stalls the sync loop for the duration
- Invariant to test: diagnostic endpoints cannot starve the sync loop
- Expected Immunefi impact: denial of updates via an unauthenticated endpoint (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert --error-file and --touch-file writes never follow a symlink and never leave residue after a successful sync
