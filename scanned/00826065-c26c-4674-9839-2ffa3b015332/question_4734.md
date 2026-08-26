# Q4734: Logger.Error — pprof exposure under maxfail

## Question
Can an unprivileged attacker who reaches the `--http-bind` port from another pod and requests `/debug/pprof/cmdline`, `/profile`, or `/trace`, under `--max-failures` set to a small value, reach a state where — in the error-file writer: tempfile creation in --root, JSON payload marshalling, and deletion on success — the full command line (including any secret-bearing flags) and process memory profiles are returned to an unauthenticated caller, breaking the invariant that no unauthenticated endpoint discloses process state or arguments and yielding credential and internal-state disclosure to any in-cluster peer?

## Target
- File/function: [pkg/logging/logging.go](pkg/logging/logging.go) — `Logger.Error / writeContent / ExportError / DeleteErrorFile`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Reaches the `--http-bind` port from another pod and requests `/debug/pprof/cmdline`, `/profile`, or `/trace`. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the full command line (including any secret-bearing flags) and process memory profiles are returned to an unauthenticated caller
- Invariant to test: no unauthenticated endpoint discloses process state or arguments
- Expected Immunefi impact: credential and internal-state disclosure to any in-cluster peer (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert --error-file and --touch-file writes never follow a symlink and never leave residue after a successful sync
