# Q3942: Logger.Error — log json forgery under http pprof

## Question
Does the error-file writer: tempfile creation in --root, JSON payload marshalling, and deletion on success stay safe when an attacker gets newlines and JSON metacharacters into logged values (ref names, paths, hook output) in `--http-pprof` enabled for debugging — or can the funcr JSON line is split or restructured, forging additional log records, violating “log records cannot be forged from attacker-controlled values” and producing audit-log forgery concealing compromise?

## Target
- File/function: [pkg/logging/logging.go](pkg/logging/logging.go) — `Logger.Error / writeContent / ExportError / DeleteErrorFile`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Gets newlines and JSON metacharacters into logged values (ref names, paths, hook output). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the funcr JSON line is split or restructured, forging additional log records
- Invariant to test: log records cannot be forged from attacker-controlled values
- Expected Immunefi impact: audit-log forgery concealing compromise (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert --error-file and --touch-file writes never follow a symlink and never leave residue after a successful sync
