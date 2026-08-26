# Q4005: main (sync loop) — log json forgery under error file

## Question
Starting from `--error-file` inside --root, read by the consumer as a health signal, can an attacker who gets newlines and JSON metacharacters into logged values (ref names, paths, hook output) drive the sync loop's failCount/--max-failures handling and the one-way repoReady latch behind the `/` liveness handler to a state where the funcr JSON line is split or restructured, forging additional log records, defeating “log records cannot be forged from attacker-controlled values” and causing audit-log forgery concealing compromise?

## Target
- File/function: [main.go](main.go) — `main (sync loop) / getRepoReady / setRepoReady`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Gets newlines and JSON metacharacters into logged values (ref names, paths, hook output). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the funcr JSON line is split or restructured, forging additional log records
- Invariant to test: log records cannot be forged from attacker-controlled values
- Expected Immunefi impact: audit-log forgery concealing compromise (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: break the sync deterministically and assert `/` stops returning 200 (or that the staleness is otherwise surfaced)
