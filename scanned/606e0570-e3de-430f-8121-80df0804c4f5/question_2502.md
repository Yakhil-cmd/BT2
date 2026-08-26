# Q2502: Logger.Error — errorfile symlink under onetime

## Question
Does the error-file writer: tempfile creation in --root, JSON payload marshalling, and deletion on success stay safe when an attacker plants a symlink at the --error-file path (repo content, or a co-tenant on the shared volume) in `--one-time` mode used as an init container — or can writeContent()'s rename-into-place writes error JSON through it, or DeleteErrorFile() removes the symlink target, violating “error-file writes never follow attacker-controlled links” and producing arbitrary file overwrite/deletion outside --root?

## Target
- File/function: [pkg/logging/logging.go](pkg/logging/logging.go) — `Logger.Error / writeContent / ExportError / DeleteErrorFile`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Plants a symlink at the --error-file path (repo content, or a co-tenant on the shared volume). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: writeContent()'s rename-into-place writes error JSON through it, or DeleteErrorFile() removes the symlink target
- Invariant to test: error-file writes never follow attacker-controlled links
- Expected Immunefi impact: arbitrary file overwrite/deletion outside --root (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert --error-file and --touch-file writes never follow a symlink and never leave residue after a successful sync
