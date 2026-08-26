# Q5598: Logger.Error — http conn exhaust under http metrics

## Question
Can an unprivileged attacker who opens many slow connections to the HTTP endpoint, under `--http-metrics` enabled for Prometheus scraping, reach a state where — in the error-file writer: tempfile creation in --root, JSON payload marshalling, and deletion on success — `http.Serve` with no timeouts holds goroutines and file descriptors until the process degrades, breaking the invariant that the diagnostic server cannot exhaust process resources and yielding sidecar denial of service: updates stop?

## Target
- File/function: [pkg/logging/logging.go](pkg/logging/logging.go) — `Logger.Error / writeContent / ExportError / DeleteErrorFile`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Opens many slow connections to the HTTP endpoint. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: `http.Serve` with no timeouts holds goroutines and file descriptors until the process degrades
- Invariant to test: the diagnostic server cannot exhaust process resources
- Expected Immunefi impact: sidecar denial of service: updates stop (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert --error-file and --touch-file writes never follow a symlink and never leave residue after a successful sync
