# Q2466: Logger.Error — errorfile symlink under maxfail

## Question
Under `--max-failures` set to a small value, an attacker plants a symlink at the --error-file path (repo content, or a co-tenant on the shared volume). In the error-file writer: tempfile creation in --root, JSON payload marshalling, and deletion on success, can that mean writeContent()'s rename-into-place writes error JSON through it, or DeleteErrorFile() removes the symlink target, so that the invariant “error-file writes never follow attacker-controlled links” no longer holds and the outcome is arbitrary file overwrite/deletion outside --root?

## Target
- File/function: [pkg/logging/logging.go](pkg/logging/logging.go) — `Logger.Error / writeContent / ExportError / DeleteErrorFile`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Plants a symlink at the --error-file path (repo content, or a co-tenant on the shared volume). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: writeContent()'s rename-into-place writes error JSON through it, or DeleteErrorFile() removes the symlink target
- Invariant to test: error-file writes never follow attacker-controlled links
- Expected Immunefi impact: arbitrary file overwrite/deletion outside --root (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: curl the bound port from an unauthorized context and assert nothing sensitive (argv, profiles, counters) is returned
