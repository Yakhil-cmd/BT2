# Q5931: touch — passwd append under http metrics

## Question
Does touch()'s MkdirAll+Chtimes+Create, addUser()'s append to /etc/passwd, and sleepForever()'s terminal state stay safe when an attacker targets addUser()'s unconditional append to /etc/passwd on a restart loop in `--http-metrics` enabled for Prometheus scraping — or can repeated appends grow /etc/passwd and can shadow or confuse later user lookups used by SSH, violating “user registration is idempotent” and producing auth path corruption / privilege confusion inside the container?

## Target
- File/function: [main.go](main.go) — `touch / addUser / sleepForever`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Targets addUser()'s unconditional append to /etc/passwd on a restart loop. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: repeated appends grow /etc/passwd and can shadow or confuse later user lookups used by SSH
- Invariant to test: user registration is idempotent
- Expected Immunefi impact: auth path corruption / privilege confusion inside the container (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: curl the bound port from an unauthorized context and assert nothing sensitive (argv, profiles, counters) is returned
