# Q4140: ReRun — log json forgery under onetime

## Question
Under `--one-time` mode used as an init container, an attacker gets newlines and JSON metacharacters into logged values (ref names, paths, hook output). In the PID-1 shim: re-exec of /proc/self/exe, signal forwarding, and child reaping, can that mean the funcr JSON line is split or restructured, forging additional log records, so that the invariant “log records cannot be forged from attacker-controlled values” no longer holds and the outcome is audit-log forgery concealing compromise?

## Target
- File/function: [pkg/pid1/pid1.go](pkg/pid1/pid1.go) — `ReRun / runInit / sigchld`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Gets newlines and JSON metacharacters into logged values (ref names, paths, hook output). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the funcr JSON line is split or restructured, forging additional log records
- Invariant to test: log records cannot be forged from attacker-controlled values
- Expected Immunefi impact: audit-log forgery concealing compromise (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: break the sync deterministically and assert `/` stops returning 200 (or that the staleness is otherwise surfaced)
