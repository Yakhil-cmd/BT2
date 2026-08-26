# Q4131: touch — log json forgery under onetime

## Question
Can an unprivileged attacker who gets newlines and JSON metacharacters into logged values (ref names, paths, hook output), under `--one-time` mode used as an init container, reach a state where — in touch()'s MkdirAll+Chtimes+Create, addUser()'s append to /etc/passwd, and sleepForever()'s terminal state — the funcr JSON line is split or restructured, forging additional log records, breaking the invariant that log records cannot be forged from attacker-controlled values and yielding audit-log forgery concealing compromise?

## Target
- File/function: [main.go](main.go) — `touch / addUser / sleepForever`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Gets newlines and JSON metacharacters into logged values (ref names, paths, hook output). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the funcr JSON line is split or restructured, forging additional log records
- Invariant to test: log records cannot be forged from attacker-controlled values
- Expected Immunefi impact: audit-log forgery concealing compromise (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert --error-file and --touch-file writes never follow a symlink and never leave residue after a successful sync
