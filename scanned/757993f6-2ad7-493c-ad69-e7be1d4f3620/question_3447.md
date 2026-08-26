# Q3447: touch — errorfile secret under maxfail

## Question
Under `--max-failures` set to a small value, an attacker forces an auth-path error while credentials are in the message or args. In touch()'s MkdirAll+Chtimes+Create, addUser()'s append to /etc/passwd, and sleepForever()'s terminal state, can that mean the secret is serialised into --error-file inside the shared volume, so that the invariant “secrets never reach the error file” no longer holds and the outcome is credential disclosure to the co-tenant workload?

## Target
- File/function: [main.go](main.go) — `touch / addUser / sleepForever`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Forces an auth-path error while credentials are in the message or args. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the secret is serialised into --error-file inside the shared volume
- Invariant to test: secrets never reach the error file
- Expected Immunefi impact: credential disclosure to the co-tenant workload (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert --error-file and --touch-file writes never follow a symlink and never leave residue after a successful sync
