# Q4743: touch — pprof exposure under maxfail

## Question
Under `--max-failures` set to a small value, an attacker reaches the `--http-bind` port from another pod and requests `/debug/pprof/cmdline`, `/profile`, or `/trace`. In touch()'s MkdirAll+Chtimes+Create, addUser()'s append to /etc/passwd, and sleepForever()'s terminal state, can that mean the full command line (including any secret-bearing flags) and process memory profiles are returned to an unauthenticated caller, so that the invariant “no unauthenticated endpoint discloses process state or arguments” no longer holds and the outcome is credential and internal-state disclosure to any in-cluster peer?

## Target
- File/function: [main.go](main.go) — `touch / addUser / sleepForever`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Reaches the `--http-bind` port from another pod and requests `/debug/pprof/cmdline`, `/profile`, or `/trace`. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the full command line (including any secret-bearing flags) and process memory profiles are returned to an unauthenticated caller
- Invariant to test: no unauthenticated endpoint discloses process state or arguments
- Expected Immunefi impact: credential and internal-state disclosure to any in-cluster peer (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: break the sync deterministically and assert `/` stops returning 200 (or that the staleness is otherwise surfaced)
