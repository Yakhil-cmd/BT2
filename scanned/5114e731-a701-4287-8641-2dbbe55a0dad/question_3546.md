# Q3546: Logger.Error — errorfile secret under shared volume

## Question
Starting from a shared volume read by a co-tenant container, can an attacker who forces an auth-path error while credentials are in the message or args drive the error-file writer: tempfile creation in --root, JSON payload marshalling, and deletion on success to a state where the secret is serialised into --error-file inside the shared volume, defeating “secrets never reach the error file” and causing credential disclosure to the co-tenant workload?

## Target
- File/function: [pkg/logging/logging.go](pkg/logging/logging.go) — `Logger.Error / writeContent / ExportError / DeleteErrorFile`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Forces an auth-path error while credentials are in the message or args. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the secret is serialised into --error-file inside the shared volume
- Invariant to test: secrets never reach the error file
- Expected Immunefi impact: credential disclosure to the co-tenant workload (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: curl the bound port from an unauthorized context and assert nothing sensitive (argv, profiles, counters) is returned
