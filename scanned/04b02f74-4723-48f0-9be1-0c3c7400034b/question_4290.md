# Q4290: repoSync.StoreCredentials — stdin credential timing under askpass

## Question
Starting from `--askpass-url` auth, re-fetched every sync, can an attacker who makes `git credential approve` slow or fail while the blob is on stdin drive StoreCredentials(): the `url=/username=/password=` blob piped into `git credential approve` to a state where the error string returned by runWithStdin() embeds command output that can contain the credential context, and it is logged, defeating “credential material never appears in error strings” and causing credential disclosure via error reporting?

## Target
- File/function: [main.go](main.go) — `repoSync.StoreCredentials`
- Entrypoint: attacker-controlled repo content or redirect target -> refreshCreds()/credential helper during the sync
- Attacker controls: Makes `git credential approve` slow or fail while the blob is on stdin. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the error string returned by runWithStdin() embeds command output that can contain the credential context, and it is logged
- Invariant to test: credential material never appears in error strings
- Expected Immunefi impact: credential disclosure via error reporting (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run a local auth endpoint / fixture remote that records what it receives and assert no credential reaches any host but the configured one
