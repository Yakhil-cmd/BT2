# Q5751: touch — http conn exhaust under onetime

## Question
Under `--one-time` mode used as an init container, an attacker opens many slow connections to the HTTP endpoint. In touch()'s MkdirAll+Chtimes+Create, addUser()'s append to /etc/passwd, and sleepForever()'s terminal state, can that mean `http.Serve` with no timeouts holds goroutines and file descriptors until the process degrades, so that the invariant “the diagnostic server cannot exhaust process resources” no longer holds and the outcome is sidecar denial of service: updates stop?

## Target
- File/function: [main.go](main.go) — `touch / addUser / sleepForever`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Opens many slow connections to the HTTP endpoint. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: `http.Serve` with no timeouts holds goroutines and file descriptors until the process degrades
- Invariant to test: the diagnostic server cannot exhaust process resources
- Expected Immunefi impact: sidecar denial of service: updates stop (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: curl the bound port from an unauthorized context and assert nothing sensitive (argv, profiles, counters) is returned
