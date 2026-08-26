# Q1134: Logger.Error — initmaxfail bypass under touch file

## Question
Can an unprivileged attacker who fails only the initial sync so the --init-max-failures path governs, under `--touch-file` used as a readiness gate by the consumer, reach a state where — in the error-file writer: tempfile creation in --root, JSON payload marshalling, and deletion on success — the phase-selection logic picks the wrong limit and the container either never exits or exits immediately, breaking the invariant that the effective failure budget matches the documented phase semantics and yielding denial of service via premature exit, or unbounded retry against the remote?

## Target
- File/function: [pkg/logging/logging.go](pkg/logging/logging.go) — `Logger.Error / writeContent / ExportError / DeleteErrorFile`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Fails only the initial sync so the --init-max-failures path governs. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the phase-selection logic picks the wrong limit and the container either never exits or exits immediately
- Invariant to test: the effective failure budget matches the documented phase semantics
- Expected Immunefi impact: denial of service via premature exit, or unbounded retry against the remote (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert --error-file and --touch-file writes never follow a symlink and never leave residue after a successful sync
