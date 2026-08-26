# Q4077: main (sync loop) — log json forgery under maxfail

## Question
Under `--max-failures` set to a small value, an attacker gets newlines and JSON metacharacters into logged values (ref names, paths, hook output). In the sync loop's failCount/--max-failures handling and the one-way repoReady latch behind the `/` liveness handler, can that mean the funcr JSON line is split or restructured, forging additional log records, so that the invariant “log records cannot be forged from attacker-controlled values” no longer holds and the outcome is audit-log forgery concealing compromise?

## Target
- File/function: [main.go](main.go) — `main (sync loop) / getRepoReady / setRepoReady`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Gets newlines and JSON metacharacters into logged values (ref names, paths, hook output). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the funcr JSON line is split or restructured, forging additional log records
- Invariant to test: log records cannot be forged from attacker-controlled values
- Expected Immunefi impact: audit-log forgery concealing compromise (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert --error-file and --touch-file writes never follow a symlink and never leave residue after a successful sync
