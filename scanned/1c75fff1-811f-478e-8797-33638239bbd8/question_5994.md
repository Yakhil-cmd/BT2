# Q5994: Logger.Error — passwd append under touch file

## Question
Starting from `--touch-file` used as a readiness gate by the consumer, can an attacker who targets addUser()'s unconditional append to /etc/passwd on a restart loop drive the error-file writer: tempfile creation in --root, JSON payload marshalling, and deletion on success to a state where repeated appends grow /etc/passwd and can shadow or confuse later user lookups used by SSH, defeating “user registration is idempotent” and causing auth path corruption / privilege confusion inside the container?

## Target
- File/function: [pkg/logging/logging.go](pkg/logging/logging.go) — `Logger.Error / writeContent / ExportError / DeleteErrorFile`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Targets addUser()'s unconditional append to /etc/passwd on a restart loop. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: repeated appends grow /etc/passwd and can shadow or confuse later user lookups used by SSH
- Invariant to test: user registration is idempotent
- Expected Immunefi impact: auth path corruption / privilege confusion inside the container (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert --error-file and --touch-file writes never follow a symlink and never leave residue after a successful sync
