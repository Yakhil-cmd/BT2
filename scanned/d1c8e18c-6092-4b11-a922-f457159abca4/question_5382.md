# Q5382: Logger.Error — metrics info leak under maxfail

## Question
Does the error-file writer: tempfile creation in --root, JSON payload marshalling, and deletion on success stay safe when an attacker scrapes `/metrics` from another pod in `--max-failures` set to a small value — or can sync counts, timings, and hook/askpass error counters reveal repository activity and auth failures to unauthorised callers, violating “metrics do not disclose sensitive operational detail to unauthenticated callers” and producing information disclosure enabling targeted follow-on attacks?

## Target
- File/function: [pkg/logging/logging.go](pkg/logging/logging.go) — `Logger.Error / writeContent / ExportError / DeleteErrorFile`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Scrapes `/metrics` from another pod. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: sync counts, timings, and hook/askpass error counters reveal repository activity and auth failures to unauthorised callers
- Invariant to test: metrics do not disclose sensitive operational detail to unauthenticated callers
- Expected Immunefi impact: information disclosure enabling targeted follow-on attacks (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: curl the bound port from an unauthorized context and assert nothing sensitive (argv, profiles, counters) is returned
