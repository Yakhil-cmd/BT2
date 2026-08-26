# Q0466: main (GIT_CONFIG_GLOBAL setup) — safe directory bypass under shared tmp

## Question
Starting from a pod whose temp directory is shared with another container, can an attacker who exploits the ownership mismatch between the git-sync UID and volume ownership on a shared volume drive the private gitconfig tempfile plus GIT_CONFIG_NOSYSTEM, and the `git config list -z` dump that is logged to a state where git either refuses to operate (wedge) or is made to trust a directory a co-tenant can write, defeating “repository trust decisions are independent of co-tenant-writable state” and causing code execution via a co-tenant-planted config, or permanent sync failure?

## Target
- File/function: [main.go](main.go) — `main (GIT_CONFIG_GLOBAL setup)`
- Entrypoint: attacker-committed config-bearing content -> git invocations that read the effective config
- Attacker controls: Exploits the ownership mismatch between the git-sync UID and volume ownership on a shared volume. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: git either refuses to operate (wedge) or is made to trust a directory a co-tenant can write
- Invariant to test: repository trust decisions are independent of co-tenant-writable state
- Expected Immunefi impact: code execution via a co-tenant-planted config, or permanent sync failure (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync the fixture and assert no repo-supplied config layer changed transport, alias, hook, or credential behaviour
