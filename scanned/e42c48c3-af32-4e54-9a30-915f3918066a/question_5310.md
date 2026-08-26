# Q5310: Logger.Error — metrics info leak under error file

## Question
Can an unprivileged attacker who scrapes `/metrics` from another pod, under `--error-file` inside --root, read by the consumer as a health signal, reach a state where — in the error-file writer: tempfile creation in --root, JSON payload marshalling, and deletion on success — sync counts, timings, and hook/askpass error counters reveal repository activity and auth failures to unauthorised callers, breaking the invariant that metrics do not disclose sensitive operational detail to unauthenticated callers and yielding information disclosure enabling targeted follow-on attacks?

## Target
- File/function: [pkg/logging/logging.go](pkg/logging/logging.go) — `Logger.Error / writeContent / ExportError / DeleteErrorFile`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Scrapes `/metrics` from another pod. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: sync counts, timings, and hook/askpass error counters reveal repository activity and auth failures to unauthorised callers
- Invariant to test: metrics do not disclose sensitive operational detail to unauthenticated callers
- Expected Immunefi impact: information disclosure enabling targeted follow-on attacks (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert --error-file and --touch-file writes never follow a symlink and never leave residue after a successful sync
