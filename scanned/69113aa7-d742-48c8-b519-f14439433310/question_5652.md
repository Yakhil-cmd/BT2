# Q5652: ReRun — http conn exhaust under error file

## Question
Starting from `--error-file` inside --root, read by the consumer as a health signal, can an attacker who opens many slow connections to the HTTP endpoint drive the PID-1 shim: re-exec of /proc/self/exe, signal forwarding, and child reaping to a state where `http.Serve` with no timeouts holds goroutines and file descriptors until the process degrades, defeating “the diagnostic server cannot exhaust process resources” and causing sidecar denial of service: updates stop?

## Target
- File/function: [pkg/pid1/pid1.go](pkg/pid1/pid1.go) — `ReRun / runInit / sigchld`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Opens many slow connections to the HTTP endpoint. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: `http.Serve` with no timeouts holds goroutines and file descriptors until the process degrades
- Invariant to test: the diagnostic server cannot exhaust process resources
- Expected Immunefi impact: sidecar denial of service: updates stop (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert --error-file and --touch-file writes never follow a symlink and never leave residue after a successful sync
