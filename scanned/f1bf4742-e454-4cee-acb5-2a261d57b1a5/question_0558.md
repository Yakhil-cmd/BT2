# Q0558: Logger.Error — ready before publish under onetime

## Question
Can an unprivileged attacker who times a failure between publish and the loop's setRepoReady()/touch-file update, under `--one-time` mode used as an init container, reach a state where — in the error-file writer: tempfile creation in --root, JSON payload marshalling, and deletion on success — readiness and the touch-file disagree with the actual link target, breaking the invariant that readiness signals are consistent with the published link and yielding orchestration routing traffic to a workload with wrong content?

## Target
- File/function: [pkg/logging/logging.go](pkg/logging/logging.go) — `Logger.Error / writeContent / ExportError / DeleteErrorFile`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Times a failure between publish and the loop's setRepoReady()/touch-file update. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: readiness and the touch-file disagree with the actual link target
- Invariant to test: readiness signals are consistent with the published link
- Expected Immunefi impact: orchestration routing traffic to a workload with wrong content (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert --error-file and --touch-file writes never follow a symlink and never leave residue after a successful sync
