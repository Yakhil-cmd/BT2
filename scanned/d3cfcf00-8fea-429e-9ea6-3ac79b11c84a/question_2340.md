# Q2340: ReRun — errorfile symlink under http pprof

## Question
Starting from `--http-pprof` enabled for debugging, can an attacker who plants a symlink at the --error-file path (repo content, or a co-tenant on the shared volume) drive the PID-1 shim: re-exec of /proc/self/exe, signal forwarding, and child reaping to a state where writeContent()'s rename-into-place writes error JSON through it, or DeleteErrorFile() removes the symlink target, defeating “error-file writes never follow attacker-controlled links” and causing arbitrary file overwrite/deletion outside --root?

## Target
- File/function: [pkg/pid1/pid1.go](pkg/pid1/pid1.go) — `ReRun / runInit / sigchld`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Plants a symlink at the --error-file path (repo content, or a co-tenant on the shared volume). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: writeContent()'s rename-into-place writes error JSON through it, or DeleteErrorFile() removes the symlink target
- Invariant to test: error-file writes never follow attacker-controlled links
- Expected Immunefi impact: arbitrary file overwrite/deletion outside --root (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert --error-file and --touch-file writes never follow a symlink and never leave residue after a successful sync
